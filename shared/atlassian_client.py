"""
Shared Atlassian Client
Common functions for JIRA and Confluence used by both Flask app and MCP server
"""

import os
import re
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Disable SSL warnings for corporate networks
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AtlassianClient:
    """Client for interacting with JIRA and Confluence APIs"""
    
    def __init__(self):
        self.url = os.environ.get("JIRA_URL", "").rstrip("/")
        self.email = os.environ.get("JIRA_EMAIL")
        self.api_token = os.environ.get("JIRA_API_TOKEN")
        self.project_key = os.environ.get("JIRA_PROJECT_KEY", "SCRUM")
    
    def is_configured(self) -> bool:
        """Check if Atlassian credentials are configured"""
        return bool(self.url and self.email and self.api_token)
    
    def _get_auth(self) -> HTTPBasicAuth:
        """Get HTTP Basic Auth"""
        return HTTPBasicAuth(self.email, self.api_token)
    
    def _get_headers(self) -> dict:
        """Get common headers"""
        return {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
    
    # ==================== JIRA Functions ====================
    
    def search_jira(self, query: str, max_results: int = 20) -> dict:
        """
        Search JIRA issues by text in summary and description.
        
        Args:
            query: Search text
            max_results: Maximum results to return
            
        Returns:
            dict with 'issues' list and 'total' count, or 'error'
        """
        if not self.is_configured():
            return {"error": "JIRA not configured", "issues": []}
        
        try:
            api_url = f"{self.url}/rest/api/3/search/jql"
            jql = f'(summary ~ "{query}" OR description ~ "{query}") ORDER BY updated DESC'
            params = {
                "jql": jql,
                "maxResults": max_results,
                "fields": "summary,status,description,updated"
            }
            
            response = requests.get(
                api_url,
                headers=self._get_headers(),
                params=params,
                auth=self._get_auth(),
                verify=False
            )
            response.raise_for_status()
            data = response.json()
            
            issues = []
            for issue in data.get("issues", []):
                fields = issue.get("fields", {})
                status_obj = fields.get("status") or {}
                issues.append({
                    "key": issue.get("key", ""),
                    "summary": fields.get("summary", ""),
                    "status": status_obj.get("name", "Unknown"),
                    "description": self._extract_description(fields.get("description"))[:300],
                    "url": f"{self.url}/browse/{issue.get('key', '')}",
                    "type": "JIRA"
                })
            
            return {"issues": issues, "total": data.get("total", 0)}
        
        except Exception as e:
            return {"error": str(e), "issues": []}
    
    def list_jira_tasks(self, jql: str = None, max_results: int = 20) -> dict:
        """
        List JIRA tasks with optional JQL filter.
        
        Args:
            jql: JQL query (default: assigned to current user)
            max_results: Maximum results
            
        Returns:
            dict with 'issues' list and 'total' count
        """
        if not self.is_configured():
            return {"error": "JIRA not configured", "issues": []}
        
        if jql is None:
            jql = "assignee = currentUser() ORDER BY updated DESC"
        
        try:
            api_url = f"{self.url}/rest/api/3/search/jql"
            params = {
                "jql": jql,
                "maxResults": max_results,
                "fields": "summary,status,duedate,assignee,priority,created,description"
            }
            
            response = requests.get(
                api_url,
                headers=self._get_headers(),
                params=params,
                auth=self._get_auth(),
                verify=False
            )
            response.raise_for_status()
            data = response.json()
            
            issues = []
            for issue in data.get("issues", []):
                fields = issue.get("fields", {})
                status_obj = fields.get("status") or {}
                assignee_obj = fields.get("assignee") or {}
                priority_obj = fields.get("priority") or {}
                
                issues.append({
                    "key": issue.get("key"),
                    "summary": fields.get("summary"),
                    "status": status_obj.get("name"),
                    "assignee": assignee_obj.get("displayName"),
                    "priority": priority_obj.get("name"),
                    "duedate": fields.get("duedate"),
                    "created": fields.get("created"),
                    "description": self._extract_description(fields.get("description")),
                    "url": f"{self.url}/browse/{issue.get('key')}"
                })
            
            return {"issues": issues, "total": data.get("total", 0)}
        
        except Exception as e:
            return {"error": str(e), "issues": []}
    
    def get_jira_issue(self, issue_key: str) -> dict:
        """
        Get details of a specific JIRA issue.
        
        Args:
            issue_key: JIRA issue key (e.g., "SCRUM-1")
            
        Returns:
            dict with issue details
        """
        if not self.is_configured():
            return {"error": "JIRA not configured"}
        
        try:
            api_url = f"{self.url}/rest/api/3/issue/{issue_key}"
            
            response = requests.get(
                api_url,
                headers=self._get_headers(),
                auth=self._get_auth(),
                verify=False
            )
            response.raise_for_status()
            issue = response.json()
            
            fields = issue.get("fields", {})
            status_obj = fields.get("status") or {}
            assignee_obj = fields.get("assignee") or {}
            reporter_obj = fields.get("reporter") or {}
            priority_obj = fields.get("priority") or {}
            issuetype_obj = fields.get("issuetype") or {}
            
            return {
                "key": issue.get("key"),
                "summary": fields.get("summary"),
                "description": self._extract_description(fields.get("description")),
                "status": status_obj.get("name"),
                "assignee": assignee_obj.get("displayName"),
                "reporter": reporter_obj.get("displayName"),
                "priority": priority_obj.get("name"),
                "issuetype": issuetype_obj.get("name"),
                "duedate": fields.get("duedate"),
                "created": fields.get("created"),
                "updated": fields.get("updated"),
                "url": f"{self.url}/browse/{issue.get('key')}"
            }
        
        except Exception as e:
            return {"error": str(e)}
    
    def create_jira_issue(self, summary: str, description: str = None, 
                          issue_type: str = "Task", priority: str = None, 
                          due_date: str = None) -> dict:
        """
        Create a new JIRA issue.
        
        Args:
            summary: Issue title
            description: Issue description
            issue_type: Type (Task, Bug, Story, etc.)
            priority: Priority level
            due_date: Due date (YYYY-MM-DD)
            
        Returns:
            dict with created issue details
        """
        if not self.is_configured():
            return {"error": "JIRA not configured"}
        
        try:
            api_url = f"{self.url}/rest/api/3/issue"
            
            payload = {
                "fields": {
                    "project": {"key": self.project_key},
                    "summary": summary,
                    "issuetype": {"name": issue_type}
                }
            }
            
            if description:
                # Convert multi-line description to ADF format
                # Split by newlines and create paragraphs
                lines = description.split('\n')
                content_blocks = []
                
                for line in lines:
                    if line.strip():  # Non-empty line
                        content_blocks.append({
                            "type": "paragraph",
                            "content": [{"type": "text", "text": line}]
                        })
                    else:  # Empty line - add empty paragraph for spacing
                        content_blocks.append({
                            "type": "paragraph",
                            "content": []
                        })
                
                # Ensure at least one paragraph
                if not content_blocks:
                    content_blocks = [{"type": "paragraph", "content": [{"type": "text", "text": description}]}]
                
                payload["fields"]["description"] = {
                    "type": "doc",
                    "version": 1,
                    "content": content_blocks
                }
            
            if priority:
                payload["fields"]["priority"] = {"name": priority}
            
            if due_date:
                payload["fields"]["duedate"] = due_date
            
            response = requests.post(
                api_url,
                json=payload,
                headers=self._get_headers(),
                auth=self._get_auth(),
                verify=False
            )
            response.raise_for_status()
            result = response.json()
            
            return {
                "success": True,
                "key": result.get("key"),
                "id": result.get("id"),
                "url": f"{self.url}/browse/{result.get('key')}",
                "message": f"Created JIRA issue {result.get('key')}"
            }
        
        except Exception as e:
            return {"error": str(e)}
    
    # ==================== Confluence Functions ====================
    
    def search_confluence(self, query: str, max_results: int = 20, full_content: bool = False) -> dict:
        """
        Search Confluence pages by text in title and content.
        
        Args:
            query: Search text
            max_results: Maximum results to return
            full_content: If True, return more content (for LLM analysis)
            
        Returns:
            dict with 'pages' list and 'total' count, or 'error'
        """
        if not self.is_configured():
            return {"error": "Confluence not configured", "pages": []}
        
        try:
            api_url = f"{self.url}/wiki/rest/api/content/search"
            # Use wildcard for better matching (e.g., "front" matches "front-load")
            search_query = query.replace("-", " ").strip()
            params = {
                "cql": f'(title ~ "{search_query}" OR text ~ "{search_query}" OR text ~ "{search_query}*") ORDER BY lastmodified DESC',
                "limit": max_results,
                "expand": "body.storage,space"
            }
            
            response = requests.get(
                api_url,
                headers=self._get_headers(),
                params=params,
                auth=self._get_auth(),
                verify=False
            )
            response.raise_for_status()
            data = response.json()
            
            # Content length: 300 for UI display, 2000 for LLM analysis
            content_limit = 2000 if full_content else 300
            
            pages = []
            for page in data.get("results", []):
                space = page.get("space", {})
                body = page.get("body", {}).get("storage", {}).get("value", "")
                # Strip HTML tags for preview
                clean_body = re.sub(r'<[^>]+>', '', body)[:content_limit]
                
                pages.append({
                    "id": page.get("id", ""),
                    "title": page.get("title", ""),
                    "space": space.get("name", ""),
                    "preview": clean_body,
                    "url": f"{self.url}/wiki{page.get('_links', {}).get('webui', '')}",
                    "type": "Confluence"
                })
            
            return {"pages": pages, "total": len(pages)}
        
        except Exception as e:
            return {"error": str(e), "pages": []}
    
    def get_confluence_page(self, page_id: str) -> dict:
        """
        Get details of a specific Confluence page.
        
        Args:
            page_id: Confluence page ID
            
        Returns:
            dict with page details
        """
        if not self.is_configured():
            return {"error": "Confluence not configured"}
        
        try:
            api_url = f"{self.url}/wiki/rest/api/content/{page_id}"
            params = {"expand": "body.storage,space,version"}
            
            response = requests.get(
                api_url,
                headers=self._get_headers(),
                params=params,
                auth=self._get_auth(),
                verify=False
            )
            response.raise_for_status()
            page = response.json()
            
            body = page.get("body", {}).get("storage", {}).get("value", "")
            clean_body = re.sub(r'<[^>]+>', '', body)
            
            return {
                "id": page.get("id"),
                "title": page.get("title"),
                "space": page.get("space", {}).get("name"),
                "content": clean_body,
                "url": f"{self.url}/wiki{page.get('_links', {}).get('webui', '')}",
                "version": page.get("version", {}).get("number")
            }
        
        except Exception as e:
            return {"error": str(e)}
    
    # ==================== Combined Search ====================
    
    def search_all(self, query: str, max_results: int = 20, full_content: bool = False) -> dict:
        """
        Search both JIRA and Confluence.
        
        Args:
            query: Search text
            max_results: Maximum results per platform
            full_content: If True, return more content for LLM analysis
            
        Returns:
            dict with 'jira_results', 'confluence_results', and any 'errors'
        """
        jira_result = self.search_jira(query, max_results)
        confluence_result = self.search_confluence(query, max_results, full_content=full_content)
        
        errors = []
        if "error" in jira_result and jira_result["error"]:
            errors.append(f"JIRA: {jira_result['error']}")
        if "error" in confluence_result and confluence_result["error"]:
            errors.append(f"Confluence: {confluence_result['error']}")
        
        return {
            "jira_results": jira_result.get("issues", []),
            "confluence_results": confluence_result.get("pages", []),
            "errors": errors if errors else None
        }
    
    # ==================== Helper Functions ====================
    
    def _extract_description(self, desc_obj) -> str:
        """Extract plain text from JIRA's Atlassian Document Format"""
        if not desc_obj:
            return ""
        if isinstance(desc_obj, str):
            return desc_obj
        
        text_parts = []
        
        def extract_text(node):
            if isinstance(node, dict):
                if node.get("type") == "text":
                    text_parts.append(node.get("text", ""))
                for child in node.get("content", []):
                    extract_text(child)
            elif isinstance(node, list):
                for item in node:
                    extract_text(item)
        
        extract_text(desc_obj)
        return " ".join(text_parts)


# Singleton instance
_client = None

def get_client() -> AtlassianClient:
    """Get shared AtlassianClient instance"""
    global _client
    if _client is None:
        _client = AtlassianClient()
    return _client
