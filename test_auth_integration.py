#!/usr/bin/env python3
"""
Simple test script to verify auth integration
"""
import requests
import json
import sys

def test_auth_integration():
    """Test the auth integration endpoints"""
    
    base_url = "http://localhost:8000"
    
    print("🧪 Testing ERP Core API Gateway Auth Integration")
    print("=" * 50)
    
    # Test 1: Health check
    print("\n1. Testing health check...")
    try:
        response = requests.get(f"{base_url}/health/")
        if response.status_code == 200:
            print("✅ Health check passed")
            print(f"   Response: {response.json()}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {str(e)}")
        return False
    
    # Test 2: API info
    print("\n2. Testing API info...")
    try:
        response = requests.get(f"{base_url}/api/v1/info/")
        if response.status_code == 200:
            print("✅ API info retrieved")
            print(f"   Service: {response.json().get('name')}")
        else:
            print(f"❌ API info failed: {response.status_code}")
    except Exception as e:
        print(f"❌ API info error: {str(e)}")
    
    # Test 3: Gateway info (should require auth)
    print("\n3. Testing gateway info (should require auth)...")
    try:
        response = requests.get(f"{base_url}/api/v1/gateway/")
        if response.status_code == 401:
            print("✅ Gateway correctly requires authentication")
        else:
            print(f"⚠️  Gateway returned: {response.status_code}")
    except Exception as e:
        print(f"❌ Gateway test error: {str(e)}")
    
    # Test 4: Auth service health
    print("\n4. Testing auth service health...")
    try:
        response = requests.get(f"{base_url}/api/v1/status/")
        if response.status_code == 200:
            print("✅ Service status retrieved")
            services = response.json().get('services', {})
            auth_status = services.get('auth_service', {}).get('status', 'unknown')
            print(f"   Auth service status: {auth_status}")
        else:
            print(f"❌ Service status failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Service status error: {str(e)}")
    
    # Test 5: API documentation
    print("\n5. Testing API documentation...")
    try:
        response = requests.get(f"{base_url}/api/schema/")
        if response.status_code == 200:
            print("✅ API schema available")
        else:
            print(f"❌ API schema failed: {response.status_code}")
    except Exception as e:
        print(f"❌ API schema error: {str(e)}")
    
    print("\n" + "=" * 50)
    print("🎉 Auth integration test completed!")
    print("\n📚 Next steps:")
    print("   - Visit http://localhost:8000/api/docs/ for API documentation")
    print("   - Visit http://localhost:8000/health/ for health status")
    print("   - Use the auth endpoints to test authentication")
    
    return True

if __name__ == "__main__":
    success = test_auth_integration()
    sys.exit(0 if success else 1) 