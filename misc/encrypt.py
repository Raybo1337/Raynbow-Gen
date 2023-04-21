import execjs

s = execjs.compile(open('misc/packagepwd.js').read())


def ms_encrypt(password, randomNum, Key):
    return s.call("encrypt", password, randomNum, Key)
