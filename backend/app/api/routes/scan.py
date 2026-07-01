from flask import Blueprint, request, jsonify, current_app
from flask_restx import Api, Resource, fields
from firebase_admin import firestore
from ...services.scanner_manager import ScannerManager
from ...services.correlation_engine import CorrelationEngine
from ...services.scoring_engine import ScoringEngine
from ...custom_engine.engine import CustomEngine
import os
import tempfile
import shutil
import zipfile
from werkzeug.utils import secure_filename
import traceback
import time

scan_bp = Blueprint('scan', __name__)
api = Api(scan_bp, doc='/docs')

# Initialize services
scanner_manager = ScannerManager()
correlation_engine = CorrelationEngine()
scoring_engine = ScoringEngine()
custom_engine = CustomEngine()

@api.route('/upload')
class ScanUpload(Resource):
    def post(self):
        """Scan uploaded source code"""
        temp_dir = None
        start_time = time.time()
        
        try:
            # Check if file is present
            if 'file' not in request.files:
                return {'error': 'No file uploaded'}, 400
            
            file = request.files['file']
            if not file.filename:
                return {'error': 'No file selected'}, 400
            
            # Get options from form data (not JSON)
            use_custom_engine = request.form.get('custom_engine', 'true').lower() == 'true'
            use_external_scanners = request.form.get('external_scanners', 'true').lower() == 'true'
            
            # Secure filename
            original_filename = file.filename
            filename = secure_filename(original_filename)
            
            # If no extension, add .txt for pasted code
            if not os.path.splitext(filename)[1]:
                # Try to detect language from content
                content_preview = file.read(1024).decode('utf-8', errors='ignore')
                file.seek(0)
                detected_lang = custom_engine._detect_language_from_content(content_preview)
                if detected_lang:
                    ext_map = {
                        'python': '.py',
                        'javascript': '.js',
                        'php': '.php',
                        'java': '.java',
                        'go': '.go',
                        'ruby': '.rb'
                    }
                    filename = f"code{ext_map.get(detected_lang, '.txt')}"
                else:
                    filename = "code.txt"
            
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(prefix='scan_upload_')
            print(f"Created temp directory: {temp_dir}")
            
            # Save file
            file_path = os.path.join(temp_dir, filename)
            file.save(file_path)
            print(f"Saved file: {file_path}")
            
            # Extract if zip
            if filename.endswith('.zip'):
                try:
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir)
                    base_dir = temp_dir
                    print(f"Extracted zip to: {temp_dir}")
                except zipfile.BadZipFile:
                    return {'error': 'Invalid ZIP file'}, 400
            else:
                base_dir = temp_dir
            
            # Run custom engine
            custom_results = []
            custom_vulns = []
            
            if use_custom_engine:
                print("Running custom engine...")
                try:
                    custom_results = custom_engine.scan_directory(base_dir)
                    custom_vulns = [v.to_dict() for v in custom_results]
                    print(f"Custom engine found {len(custom_vulns)} vulnerabilities")
                except Exception as e:
                    print(f"Custom engine error: {e}")
                    traceback.print_exc()
            
            # Run external scanners (only if enabled AND there are files to scan)
            scan_results = []
            all_vulns = []
            
            if use_external_scanners:
                print("Running external scanners...")
                try:
                    # Only run external scanners if there are files (not just empty directory)
                    if os.path.exists(base_dir) and os.listdir(base_dir):
                        scan_results = scanner_manager.run_scan(base_dir, [])
                        for result in scan_results:
                            all_vulns.extend(result.vulnerabilities)
                        print(f"External scanners found {len(all_vulns)} vulnerabilities")
                    else:
                        print("No files to scan with external scanners")
                except Exception as e:
                    print(f"Scanner error: {e}")
                    traceback.print_exc()
            else:
                print("External scanners disabled by user")
            
            # Combine all results
            all_vulns.extend(custom_vulns)
            print(f"Total vulnerabilities found: {len(all_vulns)}")
            
            # Correlate findings
            correlated = []
            if all_vulns:
                try:
                    correlated = correlation_engine.correlate(all_vulns)
                    print(f"Correlated to {len(correlated)} unique findings")
                except Exception as e:
                    print(f"Correlation error: {e}")
                    traceback.print_exc()
                    correlated = all_vulns
            
            # Calculate security score
            try:
                score = scoring_engine.calculate_score(correlated)
            except Exception as e:
                print(f"Scoring error: {e}")
                traceback.print_exc()
                # Create a default score
                from ...services.scoring_engine import SecurityScore, RiskLevel
                score = SecurityScore(
                    overall_score=100 if not correlated else 50,
                    risk_level=RiskLevel.LOW if not correlated else RiskLevel.MEDIUM,
                    category_scores={},
                    vulnerability_counts={},
                    detailed_breakdown={},
                    recommendations=['Scan completed. Review findings for details.']
                )
            
            # Save to Firestore if available
            scan_id = None
            try:
                if current_app.db:
                    scan_id = current_app.db.collection('scans').document()
                    scan_data = {
                        'scan_id': scan_id.id,
                        'timestamp': firestore.SERVER_TIMESTAMP,
                        'filename': original_filename,
                        'scanners_used': [s.name for s in scanner_manager.scanners] if use_external_scanners else ['Custom Engine Only'],
                        'vulnerabilities': correlated,
                        'security_score': {
                            'overall': score.overall_score,
                            'risk_level': score.risk_level.value,
                            'category_scores': score.category_scores,
                            'recommendations': score.recommendations
                        },
                        'summary': {
                            'total_vulnerabilities': len(correlated),
                            'by_severity': score.vulnerability_counts
                        },
                        'scan_duration': time.time() - start_time,
                        'scanners_enabled': {
                            'custom_engine': use_custom_engine,
                            'external_scanners': use_external_scanners
                        }
                    }
                    scan_id.set(scan_data)
                    print(f"Saved scan to Firestore: {scan_id.id}")
                else:
                    print("Firestore not available, skipping save")
                    scan_id = None
            except Exception as e:
                print(f"Firestore save error (ignored): {e}")
                scan_id = None
            
            # Get actual categories found
            actual_categories = list(score.category_scores.keys()) if score.category_scores else []
            
            # Prepare response
            response = {
                'scan_id': scan_id.id if scan_id else 'local_scan',
                'filename': original_filename,
                'vulnerabilities': correlated,
                'security_score': {
                    'overall': score.overall_score,
                    'risk_level': score.risk_level.value,
                    'category_scores': score.category_scores,
                    'recommendations': score.recommendations,
                    'categories_found': actual_categories
                },
                'summary': {
                    'total': len(correlated),
                    'by_severity': score.vulnerability_counts
                },
                'scanner_results': [r.to_dict() for r in scan_results] if scan_results else [],
                'custom_engine_results': custom_vulns,
                'scan_duration': round(time.time() - start_time, 2),
                'scanners_enabled': {
                    'custom_engine': use_custom_engine,
                    'external_scanners': use_external_scanners
                }
            }
            
            return response
            
        except Exception as e:
            print(f"Scan error: {e}")
            traceback.print_exc()
            return {
                'error': str(e),
                'traceback': traceback.format_exc()
            }, 500
            
        finally:
            # Cleanup
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    print(f"Cleaned up temp directory: {temp_dir}")
                except Exception as e:
                    print(f"Cleanup error: {e}")

@api.route('/scanners')
class ScannersList(Resource):
    def get(self):
        """Get list of available scanners"""
        try:
            scanners = scanner_manager.get_available_scanners()
            return {'scanners': scanners}
        except Exception as e:
            print(f"Scanners list error: {e}")
            return {'error': str(e)}, 500

@api.route('/status/<scan_id>')
class ScanStatus(Resource):
    def get(self, scan_id):
        """Get scan status and results"""
        try:
            if not current_app.db:
                return {'error': 'Database not available'}, 500
                
            doc = current_app.db.collection('scans').document(scan_id).get()
            if not doc.exists:
                return {'error': 'Scan not found'}, 404
            
            data = doc.to_dict()
            return data
            
        except Exception as e:
            print(f"Status error: {e}")
            return {'error': str(e)}, 500