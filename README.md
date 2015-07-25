# HMAC Authentication Filter

Hash-based Message Authentication Code (HMAC) implementation filter for Clyde API gateway.

> Implementation is based on [hmmac](https://github.com/cmawhorter/hmmac) module.

<!-- TOC depth:6 withLinks:1 updateOnSave:1 orderedList:0 -->

- [HMAC Authentication Filter](#hmac-authentication-filter)
	- [Configuration](#configuration)
	- [Examples](#examples)
	- [Notes](#notes)
- [License](#license)

<!-- /TOC -->

## Configuration

Filter accepts the configuration properties:

* `realm`: A string that identifies the authentication realm.
* `consumers`: An object with the list of `key` properties and `secret` values.

## Examples

### Securing a provider

Here we are configuring a provider that is accessed for any URL that starts by: `http://CLYDE_SERVER/context`.
The requests are redirected to `http://some_server` but before HMAC authentication is applied.
The authentication `realm` is `Provider's Realm` and the only available user is those that signs request with the `keyA` and applying the secret `secretA`.

```javascript
{
  "providers": [
    {
      "id": "provider",
      "context": "/context",
      "target": "https://some_server",
      "prefilters": [
        {
          "id": "hmac-auth",
          "path": "clyde-hmac-auth",
          "config": {
            "realm": "Provider's Realm",
            "consumers": {
              "keyA": "secretA"
            }
          }
        }
      ]
    }
  ]
}
```

## Notes

* It must be configured as a global or provider's prefilter. It has no sense as a postfilter.


# License

The MIT License (MIT)

Copyright (c) 2015 Antonio Santiago (@acanimal)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
