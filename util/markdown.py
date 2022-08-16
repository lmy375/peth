
def make_table(headers, data):
    """
    headers [A, B]
    data [
        (1, 2),
        (2, 3)
    ]
    """
    txt = '|' +  '|'.join(headers) + '|\n' 
    txt += '|---' * len(headers) + '|\n'
    for line in data:
        txt += '|' +  '|'.join(line) + '|\n'
    return txt

def make_attr_table(data):
    """
    data [
        (a, [attr1, attr2]),
        (b, [attr1]),
        (c, [attr2])
    ]
    """
    headers = set()
    for _, attrs in data:
        headers = headers.union(attrs)
    
    if headers:
        # Move "only" values to front.
        headers = list(headers)
        headers.sort()
        left = []
        right = []
        for i in headers:
            if 'only' in i.lower():
                left.append(i)
            else:
                right.append(i)
        headers = left + right
        
        txt = '| |' +  '|'.join(headers) + '|\n' 
    else:
        txt = '| |\n'
    txt += '|---' * (len(headers) + 1) + '|\n'
    for obj, attrs in data:
        txt += "|" + obj
        for attr in headers:
            if attr in attrs:
                txt += '| [✓] '
            else:
                txt += '| '
        txt += "|\n"
    return txt

