from flask import Blueprint, request, jsonify, current_app
from flask_restx import Api, Resource, fields
from ...services.report_generator import ReportGenerator
from ...enrichers.cwe_mapping import CWEMapper
import json

reports_bp = Blueprint('reports', __name__)
api = Api(reports_bp, doc='/docs')

report_generator = ReportGenerator()

@api.route('/<scan_id>')
class Report(Resource):
    def get(self, scan_id):
        """Generate a report for a specific scan"""
        try:
            # Get scan data from Firestore
            doc = current_app.db.collection('scans').document(scan_id).get()
            if not doc.exists:
                # Try github_scans collection
                doc = current_app.db.collection('github_scans').document(scan_id).get()
                if not doc.exists:
                    return {'error': 'Scan not found'}, 404
            
            scan_data = doc.to_dict()
            
            # Get format from query parameter
            format_type = request.args.get('format', 'json')
            
            # Generate report
            if format_type == 'html':
                report_content = report_generator.generate_html_report(scan_data)
                return report_content, 200, {'Content-Type': 'text/html'}
            elif format_type == 'md':
                report_content = report_generator.generate_markdown_report(scan_data)
                return report_content, 200, {'Content-Type': 'text/markdown'}
            else:
                report_content = report_generator.generate_json_report(scan_data)
                return report_content, 200, {'Content-Type': 'application/json'}
                
        except Exception as e:
            return {'error': str(e)}, 500

@api.route('/<scan_id>/enriched')
class EnrichedReport(Resource):
    def get(self, scan_id):
        """Get enriched report with CWE/CVSS/OWASP information"""
        try:
            # Get scan data from Firestore
            doc = current_app.db.collection('scans').document(scan_id).get()
            if not doc.exists:
                doc = current_app.db.collection('github_scans').document(scan_id).get()
                if not doc.exists:
                    return {'error': 'Scan not found'}, 404
            
            scan_data = doc.to_dict()
            
            # Enrich vulnerabilities
            enriched_vulns = []
            for vuln in scan_data.get('vulnerabilities', []):
                enriched = CWEMapper.enrich_vulnerability(vuln)
                enriched_vulns.append(enriched)
            
            scan_data['vulnerabilities'] = enriched_vulns
            
            return scan_data
            
        except Exception as e:
            return {'error': str(e)}, 500

@api.route('/<scan_id>/summary')
class ReportSummary(Resource):
    def get(self, scan_id):
        """Get a summary report"""
        try:
            # Get scan data from Firestore
            doc = current_app.db.collection('scans').document(scan_id).get()
            if not doc.exists:
                doc = current_app.db.collection('github_scans').document(scan_id).get()
                if not doc.exists:
                    return {'error': 'Scan not found'}, 404
            
            scan_data = doc.to_dict()
            
            # Create summary
            summary = {
                'scan_id': scan_id,
                'timestamp': scan_data.get('timestamp'),
                'total_vulnerabilities': len(scan_data.get('vulnerabilities', [])),
                'security_score': scan_data.get('security_score', {}),
                'summary': scan_data.get('summary', {}),
                'risk_level': scan_data.get('security_score', {}).get('risk_level', 'unknown'),
                'recommendations': scan_data.get('security_score', {}).get('recommendations', [])
            }
            
            return summary
            
        except Exception as e:
            return {'error': str(e)}, 500
