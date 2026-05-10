# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.7
# *
# * Copyright 2026. Benoit Michau.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
# * MA 02110-1301  USA
# *
# *--------------------------------------------------------
# * File Name : pycrate_core/log.py
# * Created : 2026-04-26
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import logging

# pycrate lib-level logger
# by default, the lib won't do anything with the generated logs
# it's up the the application to configure this

logger = logging.getLogger('pycrate')
logger.setLevel(logging.INFO)
logger.addHandler(logging.NullHandler())

# typical format for pycrate logging
logfmt = logging.Formatter(
    fmt='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(filename)s:%(lineno)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
    )
