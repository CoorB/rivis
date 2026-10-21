#!/usr/bin/python3 -I
"""Select DocumentsUI controls by resource ID and verify the Downloads root."""
import sys
import xml.etree.ElementTree as ET


def doc_id(node, suffix=None):
    value = node.get('resource-id', '')
    return 'documentsui:id/' in value and (suffix is None or value.endswith(':id/' + suffix))


def nodes(xml):
    return list(ET.fromstring(xml).iter('node'))


def center(node):
    import re
    coords = [int(n) for n in re.findall(r'\d+', node.get('bounds', ''))]
    return '%d %d' % ((coords[0] + coords[2]) // 2, (coords[1] + coords[3]) // 2) if len(coords) == 4 else ''


def choose(xml, action):
    found = nodes(xml)
    if action == 'drawer':
        for n in found:
            if doc_id(n, 'roots_list'):
                return 'OPEN'
        for n in found:
            if doc_id(n, 'toolbar'):
                for child in n.iter('node'):
                    if child.get('content-desc') in ('Show roots', 'Open navigation drawer'):
                        return center(child)
        return ''
    if action == 'downloads':
        for n in found:
            if doc_id(n, 'roots_list'):
                for child in n.iter('node'):
                    if child.get('text') == 'Downloads':
                        return center(child)
        return ''
    # The current root must be visible in the DocumentsUI toolbar before selecting a file.
    toolbar = next((n for n in found if doc_id(n, 'toolbar')), None)
    if toolbar is None or not any(n.get('text') == 'Downloads' for n in toolbar.iter('node')):
        return ''
    for n in found:
        if n.get('text') == 'proxy-ca.crt' and doc_id(n):
            return center(n)
    return ''


if __name__ == '__main__':
    print(choose(sys.stdin.read(), sys.argv[1]))
