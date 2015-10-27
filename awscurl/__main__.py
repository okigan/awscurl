#!/usr/bin/env python
"""The main entry point. Invoke as `awscurl' or `python -m awscurl'.

"""
import sys
from .awscurl import main


if __name__ == '__main__':
    sys.exit(main())
