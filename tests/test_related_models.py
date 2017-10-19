from app_fixtures import app
from restful_ben.test_utils import json_call, login, dict_contains, iso_regex

def test_expansion(app):
    test_client = app.test_client()
    login(test_client)

    response = json_call(test_client.get, '/cats?$expand=owner')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 3
    assert dict_contains(response.json['data'][0], {
        'id': 1,
        'name': 'Ada',
        'age': 5,
        'pattern': 'Tabby',
        'updated_at': iso_regex,
        'created_at': iso_regex
    })
    assert dict_contains(response.json['data'][0]['owner'], {
        'id': 1,
        'active': True,
        'role': 'admin',
        'email': 'amadonna@example.com',
        'created_at': iso_regex,
        'updated_at': iso_regex
    })

    response = json_call(test_client.get, '/cats')
    assert response.status_code == 200
    assert response.json['count'] == 3
    assert response.json['page'] == 1
    assert response.json['total_pages'] == 1
    assert len(response.json['data']) == 3
    assert response.json['data'][0]['owner'] == 1
