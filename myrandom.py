# -*- coding: utf-8 -*-

import random
import string

def getRandomString(len=12):
    seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    sa = []
    for i in range(len):
        sa.append(random.choice(seed))
    return ''.join(sa)