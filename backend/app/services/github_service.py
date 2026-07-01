import os
import shutil
import tempfile
import subprocess
import re
from typing import Optional, Dict, Any
from urllib.parse import urlparse
import time

class GitHubService:
    """Service for GitHub repository integration"""
    
    def __init__(self):
        self.temp_dir = None
        self.max_repo_size = 100 * 1024 * 1024  # 100MB limit
        self.timeout = 300  # 5 minutes
    
    def clone_repository(self, repo_url: str) -> Optional[str]:
        """
        Clone a GitHub repository securely
        Returns the local path to the cloned repository
        """
        # Validate URL
        if not self._validate_github_url(repo_url):
            raise ValueError(f"Invalid GitHub URL: {repo_url}")
        
        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp(prefix='github_repo_')
        
        try:
            # Clone with depth=1 for faster cloning
            cmd = [
                'git', 'clone',
                '--depth', '1',
                '--single-branch',
                repo_url,
                self.temp_dir
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                raise Exception(f"Failed to clone repository: {result.stderr}")
            
            # Check repository size
            size = self._get_repo_size(self.temp_dir)
            if size > self.max_repo_size:
                raise Exception(f"Repository too large: {size / 1024 / 1024:.2f}MB > {self.max_repo_size / 1024 / 1024:.0f}MB")
            
            return self.temp_dir
            
        except subprocess.TimeoutExpired:
            self._cleanup()
            raise Exception("Repository clone timed out")
        except Exception as e:
            self._cleanup()
            raise e
    
    def _validate_github_url(self, url: str) -> bool:
        """Validate GitHub repository URL"""
        # GitHub URL patterns
        patterns = [
            r'^https://github\.com/[a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_]+/?$',
            r'^https://github\.com/[a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_]+\.git$',
            r'^git@github\.com:[a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_]+\.git$',
        ]
        
        return any(re.match(pattern, url) for pattern in patterns)
    
    def _get_repo_size(self, path: str) -> int:
        """Get repository size in bytes"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.exists(fp):
                    total_size += os.path.getsize(fp)
        return total_size
    
    def _cleanup(self):
        """Clean up temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                print(f"Error cleaning up temp directory: {e}")
        self.temp_dir = None
    
    def get_repo_info(self, repo_url: str) -> Dict[str, Any]:
        """Get repository information"""
        parsed = urlparse(repo_url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) >= 2:
            return {
                'owner': path_parts[0],
                'repo': path_parts[1],
                'url': repo_url,
                'clone_url': f"https://github.com/{path_parts[0]}/{path_parts[1]}.git"
            }
        return {}
    
    def cleanup(self):
        """Public method to cleanup resources"""
        self._cleanup()