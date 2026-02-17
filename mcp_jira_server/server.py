"""
Atlassian MCP Server
Provides tools for interacting with JIRA and Confluence via Model Context Protocol
"""

import os
import sys
import json

# Add parent directory to path for shared module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Load environment variables from parent directory
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# Import shared client
from shared.atlassian_client import get_client

# Create MCP server
mcp = FastMCP("Atlassian Server")


# ==================== JIRA Tools ====================

@mcp.tool()
def search_jira(query: str, max_results: int = 20) -> str:
    """
    Search JIRA issues by text in summary and description.
    
    Args:
        query: Search text to find in issues
        max_results: Maximum number of results (default: 20)
    
    Returns:
        JSON string with matching JIRA issues
    """
    client = get_client()
    result = client.search_jira(query, max_results)
    return json.dumps(result, indent=2)


@mcp.tool()
def list_jira_tasks(jql: str = None, max_results: int = 20) -> str:
    """
    List JIRA tasks/issues.
    
    Args:
        jql: JQL query string (default: assigned to current user)
        max_results: Maximum number of results to return (default: 20)
    
    Returns:
        JSON string with list of JIRA issues
    """
    client = get_client()
    result = client.list_jira_tasks(jql, max_results)
    return json.dumps(result, indent=2)


@mcp.tool()
def get_jira_task(issue_key: str) -> str:
    """
    Get details of a specific JIRA issue.
    
    Args:
        issue_key: The JIRA issue key (e.g., "SCRUM-1")
    
    Returns:
        JSON string with issue details
    """
    client = get_client()
    result = client.get_jira_issue(issue_key)
    return json.dumps(result, indent=2)


@mcp.tool()
def create_jira_task(summary: str, description: str = None, issue_type: str = "Task", 
                     priority: str = None, due_date: str = None) -> str:
    """
    Create a new JIRA issue.
    
    Args:
        summary: The issue summary/title (required)
        description: The issue description (optional)
        issue_type: Type of issue - Task, Bug, Story, etc. (default: Task)
        priority: Priority - Highest, High, Medium, Low, Lowest (optional)
        due_date: Due date in YYYY-MM-DD format (optional)
    
    Returns:
        JSON string with created issue details
    """
    client = get_client()
    result = client.create_jira_issue(summary, description, issue_type, priority, due_date)
    return json.dumps(result, indent=2)


# ==================== Confluence Tools ====================

@mcp.tool()
def search_confluence(query: str, max_results: int = 20) -> str:
    """
    Search Confluence pages by text in title and content.
    
    Args:
        query: Search text to find in pages
        max_results: Maximum number of results (default: 20)
    
    Returns:
        JSON string with matching Confluence pages
    """
    client = get_client()
    result = client.search_confluence(query, max_results)
    return json.dumps(result, indent=2)


@mcp.tool()
def get_confluence_page(page_id: str) -> str:
    """
    Get details of a specific Confluence page.
    
    Args:
        page_id: The Confluence page ID
    
    Returns:
        JSON string with page details including content
    """
    client = get_client()
    result = client.get_confluence_page(page_id)
    return json.dumps(result, indent=2)


# ==================== Combined Search ====================

@mcp.tool()
def search_all(query: str, max_results: int = 20) -> str:
    """
    Search both JIRA and Confluence for a query.
    
    Args:
        query: Search text to find across both platforms
        max_results: Maximum results per platform (default: 20)
    
    Returns:
        JSON string with results from both JIRA and Confluence
    """
    client = get_client()
    result = client.search_all(query, max_results)
    return json.dumps(result, indent=2)


if __name__ == "__main__":
    # Disable SSL warnings for development
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Run the server
    mcp.run()
