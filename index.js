const express = require('express')
const fs = require('fs');
const app = express()
const port = 3000


const client_secret = process.env.CLIENT_SECRET
const client_id = '38c53abf6a4cf6666d15'
const urlbase='http://localhost:5173/'

app.get('/callback', async (req, res) => {
  const code = req.query['code']
  const redirect = req.query['state']
  const apiRes = await fetch('https://github.com/login/oauth/access_token',
    {
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      method: "POST",
      body: JSON.stringify({ client_id, client_secret, code })
    })
  const resJson = await apiRes.json()

  // this code is good for a demo but not for a production because anyone can use this service to authenticate github for every site
  const redirectUrl=urlbase+'?path='+redirect+'&state='+btoa(resJson)

  
  res.redirect(redirectUrl);

})

app.get('/', (req, res) => {
  res.send(`
<html>
  <head>
  </head>
  <body>
    <p>
      We're going to now talk to the GitHub API. Ready?
      <a href="https://github.com/login/oauth/authorize?scope=user:email%20repo&client_id=${client_id}">Click here</a> to begin!
    </p>
  </body>
</html>
`)
})
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
