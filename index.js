const express = require('express');
const axios = require('axios');
const { URL } = require('url');

const app = express();
const PORT = 3000;

app.use(express.static('public'));

app.get('/proxy', async (req, res) => {
    try {
        const { url, pageUrl: requestPageUrl } = req.query;
        if (!url) {
            return res.status(400).send('URL is required');
        }

        const targetUrl = new URL(url);
        const referer = requestPageUrl || targetUrl.origin;

        const response = await axios.get(url, {
            responseType: 'arraybuffer',
            headers: {
                'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': req.headers['accept'] || '*/*',
                'Accept-Language': req.headers['accept-language'] || 'ja,en-US;q=0.9,en;q=0.8',
                'Referer': referer,
                'Origin': targetUrl.origin,
                'Cookie': req.headers['cookie'] || '',
            },
            maxRedirects: 5,
            validateStatus: status => status >= 200 && status < 400,
        });

        if (response.status >= 300 && response.status < 400 && response.headers.location) {
            const redirectUrl = new URL(response.headers.location, url).href;
            return res.redirect(`/proxy?url=${encodeURIComponent(redirectUrl)}&pageUrl=${encodeURIComponent(url)}`);
        }

        const contentType = response.headers['content-type'] || '';
        
        if (response.headers['set-cookie']) {
            res.set('set-cookie', response.headers['set-cookie']);
        }

        res.removeHeader('X-Frame-Options');
        res.removeHeader('Content-Security-Policy');

        if (!contentType.includes('text/html')) {
            res.set('Content-Type', contentType);
            return res.send(response.data);
        }

        let html = Buffer.from(response.data).toString('utf-8');
        const pageUrl = url;

        const proxifyUrl = (path, parentUrl) => {
            if (!path || path.startsWith('data:') || path.startsWith('javascript:') || path.startsWith('#') || path.startsWith('blob:')) {
                return path;
            }
            try {
                const absoluteUrl = new URL(path, parentUrl).href;
                return `/proxy?url=${encodeURIComponent(absoluteUrl)}&pageUrl=${encodeURIComponent(parentUrl)}`;
            } catch (e) {
                return path;
            }
        };

        const injectedScript = `
<script>
    (function() {
        const pageUrl = '${pageUrl.replace(/'/g, "\\'")}';
        const getProxiedUrl = (u) => {
            if (typeof u !== 'string' || u.startsWith('blob:') || u.startsWith('data:') || u.startsWith(window.location.origin)) return u;
            try { return '/proxy?url=' + encodeURIComponent(new URL(u, pageUrl).href) + '&pageUrl=' + encodeURIComponent(pageUrl); }
            catch(e) { return u; }
        };
        const _fetch = window.fetch;
        window.fetch = function(r, i) {
            if (typeof r === 'string') r = getProxiedUrl(r);
            else if (r instanceof Request) r = new Request(getProxiedUrl(r.url), r);
            return _fetch.call(this, r, i);
        };
        const _open = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(m, u, ...rest) {
            return _open.apply(this, [m, getProxiedUrl(u), ...rest]);
        };
    })();
</script>
`;
        html = html.replace(/<head[^>]*>/i, `$&${injectedScript}`);
        html = html.replace(/(src|href|action|formaction)=["']([^"']*)["']/gi, (m, a, v) => `${a}="${proxifyUrl(v, pageUrl)}"`);
        html = html.replace(/url\((?!['"]?data:)([^)]+)\)/gi, (m, v) => `url("${proxifyUrl(v.trim().replace(/^['"]|['"]$/g, ''), pageUrl)}")`);
        
        html = html.replace(/integrity=["'][^"']*["']/gi, '');
        html = html.replace(/<meta http-equiv="Content-Security-Policy"[^>]*>/gi, '');

        res.set('Content-Type', 'text/html; charset=utf-8');
        res.send(html);

    } catch (error) {
        console.error("Proxy error:", error.message);
        res.status(500).send(`<h1>Vecto Proxy Error</h1><p>${error.message}</p>`);
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
