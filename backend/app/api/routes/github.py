from flask import Blueprint, request, jsonify, current_app
from flask_restx import Api, Resource, fields
from firebase_admin import firestore
from ...services.github_service import GitHubService
from ...services.scanner_manager import ScannerManager
from ...services.correlation_engine import CorrelationEngine
from ...services.scoring_engine import ScoringEngine
from ...custom_engine.engine import CustomEngine
import traceback
import time

github_bp = Blueprint('github', __name__)
api = Api(github_bp, doc='/docs')

github_request_model = api.model('GitHubRequest', {
    'repo_url': fields.String(required=True),
    'scanners': fields.List(fields.String),
    'custom_engine': fields.Boolean(default=True),
    'external_scanners': fields.Boolean(default=True)
})

github_service = GitHubService()
scanner_manager = ScannerManager()
correlation_engine = CorrelationEngine()
scoring_engine = ScoringEngine()
custom_engine = CustomEngine()

@api.route('/scan')
class GitHubScan(Resource):
    @api.expect(github_request_model)
    def post(self):
        """Scan a GitHub repository"""
        repo_path = None
        start_time = time.time()
        
        try:
            data = request.json
            repo_url = data.get('repo_url')
            
            if not repo_url:
                return {'error': 'Repository URL is required'}, 400
            
            use_custom_engine = data.get('custom_engine', True)
            use_external_scanners = data.get('external_scanners', True)
            
            print(f"Cloning repository: {repo_url}")
            
            # Clone repository
            try:
                repo_path = github_service.clone_repository(repo_url)
                print(f"Repository cloned to: {repo_path}")
            except Exception as e:
                print(f"Clone error: {e}")
                return {'error': f'Failed to clone repository: {str(e)}'}, 400
            
            # Run custom engine
            custom_results = []
            custom_vulns = []
            
            if use_custom_engine:
                print("Running custom engine...")
                try:
                    custom_results = custom_engine.scan_directory(repo_path)
                    custom_vulns = [v.to_dict() for v in custom_results]
                    print(f"Custom engine found {len(custom_vulns)} vulnerabilities")
                except Exception as e:
                    print(f"Custom engine error: {e}")
                    traceback.print_exc()
            
            # Run external scanners
            scan_results = []
            all_vulns = []
            
            if use_external_scanners:
                print("Running external scanners...")
                try:
                    scanner_names = data.get('scanners', [])
                    scan_results = scanner_manager.run_scan(repo_path, scanner_names)
                    for result in scan_results:
                        all_vulns.extend(result.vulnerabilities)
                    print(f"External scanners found {len(all_vulns)} vulnerabilities")
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
                from ...services.scoring_engine import SecurityScore, RiskLevel
                score = SecurityScore(
                    overall_score=100 if not correlated else 50,
                    risk_level=RiskLevel.LOW if not correlated else RiskLevel.MEDIUM,
                    category_scores={},
                    vulnerability_counts={},
                    detailed_breakdown={},
                    recommendations=['Scan completed. Review findings for details.']
                )
            
            # Get repo info
            repo_info = github_service.get_repo_info(repo_url)
            
            # Save to Firestore if available
            scan_id = None
            try:
                if current_app.db:
                    scan_id = current_app.db.collection('github_scans').document()
                    scan_data = {
                        'scan_id': scan_id.id,
                        'timestamp': firestore.SERVER_TIMESTAMP,
                        'repo_url': repo_url,
                        'repo_info': repo_info,
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
            except Exception as e:
                print(f"Firestore save error (ignored): {e}")
            
            # Cleanup
            github_service.cleanup()
            
            return {
                'scan_id': scan_id.id if scan_id else 'local_scan',
                'repo_info': repo_info,
                'vulnerabilities': correlated,
                'security_score': {
                    'overall': score.overall_score,
                    'risk_level': score.risk_level.value,
                    'category_scores': score.category_scores,
                    'recommendations': score.recommendations
                },
                'summary': {
                    'total': len(correlated),
                    'by_severity': score.vulnerability_counts
                },
                'scan_duration': round(time.time() - start_time, 2),
                'scanners_enabled': {
                    'custom_engine': use_custom_engine,
                    'external_scanners': use_external_scanners
                }
            }
                
        except Exception as e:
            print(f"GitHub scan error: {e}")
            traceback.print_exc()
            if repo_path:
                try:
                    github_service.cleanup()
                except:
                    pass
            return {'error': str(e)}, 500