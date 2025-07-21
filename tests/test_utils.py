import os
import sys
import pytest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from myUtils import convert_response_to_dict


def test_convert_response_to_dict_valid_json():
    json_str = '{"foo": "bar"}'
    result = convert_response_to_dict(json_str)
    assert result == {"foo": "bar"}


def test_convert_response_to_dict_invalid_json():
    invalid_json = 'not a json'
    result = convert_response_to_dict(invalid_json)
    assert result == {}
