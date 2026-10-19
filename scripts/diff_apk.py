# -*- coding: utf-8 -*-
# language: Python 3, file: diff_apk.py — 逐条目对比两个 APK, 找出被改动的文件
import sys, zipfile, hashlib

def load(path):
    z = zipfile.ZipFile(path)
    m = {}
    for i in z.infolist():
        try:
            d = z.read(i.filename)
        except Exception:
            continue
        m[i.filename] = (i.file_size, i.compress_size, i.compress_type, hashlib.sha256(d).hexdigest(), d)
    z.close()
    return m


def main(a, b):
    A = load(a)
    B = load(b)
    print('A=%s  条目 %d' % (a.split('\\')[-1], len(A)))
    print('B=%s  条目 %d' % (b.split('\\')[-1], len(B)))
    onlyA = sorted(set(A) - set(B))
    onlyB = sorted(set(B) - set(A))
    print('\n=== 只在 A(原版) 里有 (%d) ===' % len(onlyA))
    for n in onlyA[:30]:
        print('   %-60s %d' % (n, A[n][0]))
    print('\n=== 只在 B(破解版) 里有 (%d) ===' % len(onlyB))
    for n in onlyB[:30]:
        print('   %-60s %d' % (n, B[n][0]))
    same = 0
    diff = []
    for n in sorted(set(A) & set(B)):
        if A[n][3] == B[n][3]:
            same += 1
        else:
            diff.append(n)
    print('\n=== 内容相同: %d ===' % same)
    print('=== 内容不同: %d ===' % len(diff))
    for n in diff:
        da = A[n][4]
        db = B[n][4]
        first = None
        for i in range(min(len(da), len(db))):
            if da[i] != db[i]:
                first = i
                break
        print('   %-46s A=%d  B=%d  diff=%+d  首个不同偏移=%s'
              % (n[:46], len(da), len(db), len(db) - len(da),
                 ('0x%x' % first) if first is not None else '仅长度不同'))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
