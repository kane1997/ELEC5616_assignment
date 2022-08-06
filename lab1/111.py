def find_collision(ntries):
    from hashlib import sha256
    str1 = 'Frank is one of the "best" students topicId{%d} '
    str2 = 'Frank is one of the "top" students topicId{%d} '
    seen = {}
    for n in xrange(ntries):
        h = sha256(str1 % n).digest()[:4].encode('hex')
        seen[h] = n
    for n in xrange(ntries):
        h = sha256(str2 % n).digest()[:4].encode('hex')
        if h in seen:
            print str1 % seen[h]
            print str2 % n


find_collision(100000)
