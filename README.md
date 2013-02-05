# :sparkles: Sparkle Motion :sparkles:

Sparkle Motion manages appcasts and application binaries in S3, making
[Sparkle](http://sparkle.andymatuschak.org/) updates a dance in the park.

![](https://s3.amazonaws.com/f.cl.ly/items/3L1Y1m0X2c1V323v1o0V/Screen%20Shot%202013-02-05%20at%202.22.44%20PM.png)

## Getting Started

It is a tiny web application, so the easiest way to get started is to deploy
to [Heroku](https://www.heroku.com/).

### S3

If you don't have a [S3](https://aws.amazon.com/s3/) bucket set up yet, go do
that now. While you're in the [AWS
console](https://console.aws.amazon.com/s3/home?region=us-east-1), get
credentials for a new user in
[IAM](https://console.aws.amazon.com/iam/home?region=us-east-1) that only has
the permissions needed to access the S3 bucket:

```
{
  "Statement": [
    {
      "Action": [
        "s3:*"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::YOUR_BUCKET",
        "arn:aws:s3:::YOUR_BUCKET/*"
      ]
    }
  ]
}
```

### Heroku

You will need a Heroku account and the [Heroku
Toolbelt](https://toolbelt.heroku.com/) installed to deploy.

```
git clone git://github.com/titanous/sparklemotion.git
cd sparklemotion
heroku create -b https://github.com/kr/heroku-buildpack-go.git
```

Heroku will create an app and tell you the URL (eg.
`https://sparkle-motion-42.herokuapp.com`).

### GitHub

Sparkle Motion uses GitHub for authentication, so [create a new
app](https://github.com/settings/applications/new). Set the `Main URL` to the
URL of your new Heroku app. The `Callback URL` should be
`https://APP_DOMAIN/auth/return` where `APP_DOMAIN` is the domain of your Heroku
app.


### Configuration

```
heroku config:add \
  APP_NAME=<the name of your application (no spaces)> \
  AWS_ACCESS_KEY_ID=<from the IAM S3 user> \
  AWS_SECRET_ACCESS_KEY=<from the IAM S3 user> \
  S3_BUCKET=<the name of the S3 bucket> \
  GITHUB_CLIENT_ID=<from the GitHub app> \
  GITHUB_CLIENT_SECRET=<from the GitHub app> \
  BASE_URL=<the Heroku app URL> \
  AUTHORIZED_USERS=<comma separated GitHub usernames> \
  REQUIRE_SIGNATURE=1 # remove this line if you sign apps with a certificate from Apple \
  COOKIE_SECRET=$(openssl rand -hex 16 | tr -d '\r\n')
```

### Deploy :metal:

```
git push heroku master
heroku open
```

## Usage

Pushing to the `stable` channel will also push to the `beta` and `alpha`
channels, and pushing to the `beta` channel will also push to the `alpha`
channel.

### URLs

**Alpha Appcast**: `https://s3.amazonaws.com/BUCKET/APPNAME-alpha.xml`

**Beta Appcast**: `https://s3.amazonaws.com/BUCKET/APPNAME-beta.xml`

**Stable Appcast**: `https://s3.amazonaws.com/BUCKET/APPNAME-stable.xml`

**Application Release**: `https://s3.amazonaws.com/BUCKET/APPNAME-VERSION.EXT`

**Release Notes**: `https://s3.amazonaws.com/BUCKET/APPNAME-VERSION.html`

:sparkles: :dizzy: :dancer: :star2:

![](https://gs1.wac.edgecastcdn.net/8019B6/data.tumblr.com/tumblr_m5k2t6bUKb1qzc8l4o1_250.gif)
