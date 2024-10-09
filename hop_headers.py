def test_hop_by_hop_headers(url, headers):
    import requests
    response = requests.get(url, headers=headers)
    print(f"Testing URL: {url}")
    print(f"Headers: {headers}")
    if 'X-Forwarded-For' in response.headers:
        print('Server does not treat X-Forwarded-For as hop-by-hop')
    else:
        print('Server treats X-Forwarded-For as hop-by-hop')
    print("---")