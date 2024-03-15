#!/usr/bin/env python


from unittest import TestCase

from awscurl import awscurl

__author__ = 'iokulist'

import unittest
from typing import Dict, Tuple, Union, IO
from awscurl.awscurl import process_form_data  

class TestProcessFormData(unittest.TestCase):
    def test_single_file_upload(self):
        form_data = ['profile=@README.md']
        result = process_form_data(form_data)
        self.assertIn('profile', result)
        self.assertTrue(isinstance(result['profile'], Tuple))
        self.assertEqual(result['profile'][0], 'README.md')

    def test_file_upload_with_mime(self):
        form_data = ['document=@README.md;type=application/pdf']
        result = process_form_data(form_data)
        self.assertIn('document', result)
        self.assertTrue(isinstance(result['document'], Tuple))
        self.assertEqual(result['document'][0], 'README.md')
        self.assertEqual(result['document'][2], 'application/pdf')

    def test_multiple_file_uploads(self):
        form_data = [
            'photo=@README.md',
            'resume=@LICENSE;type=application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ]
        result = process_form_data(form_data)
        self.assertIn('photo', result)
        self.assertIn('resume', result)
        self.assertTrue(isinstance(result['photo'], Tuple))
        self.assertTrue(isinstance(result['resume'], Tuple))
        self.assertEqual(result['resume'][2], 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')

if __name__ == '__main__':
    unittest.main()

