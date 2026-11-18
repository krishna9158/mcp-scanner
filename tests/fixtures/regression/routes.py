"""
Routes for test fixture app with unsafe authorization and CORS.
"""
import requests

# 11. Unsafe Endpoint Authorization (Missing Tenant ID in Query)
def get_order_details(order_id, tenant_id):
    query = "SELECT * FROM orders WHERE id = :id"
    return query


# Unsafe CORS configuration
def configure_cors(app):
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"
    }
    return headers
