import sys

new_content = '''<!-- gpgkey.html -->
{% extends 'base.html' %}

{% block title %}GPG Key{% endblock %}

{% block styles %}
    {{ super() }}
    <style>
        /* Premium Cryptographic Dark Theme for GPG Page */
        .container { max-width: 1000px; }
        
        .page-heading h1 {
            font-weight: 800;
            letter-spacing: -0.5px;
            color: #0f172a;
            margin-bottom: 2rem;
            margin-top: 1rem;
        }

        .card {
            background: #1e293b !important;
            border: 1px solid #334155;
            box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.4) !important;
            border-radius: 16px;
            color: #f8fafc;
            overflow: hidden;
            width: 100%;
        }

        .card-body {
            padding: 2.5rem;
        }

        .card-title {
            color: #f8fafc;
            font-weight: 700;
            letter-spacing: 0.5px;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .card-title i {
            color: #10b981;
        }

        #fingerprint.form-control {
            background-color: #0f172a !important;
            border: 1px solid #334155;
            color: #10b981 !important;
            font-family: 'Courier New', Courier, monospace;
            font-weight: bold;
            padding: 14px 15px;
            font-size: 1rem;
        }

        pre {
            background-color: #0f172a !important;
            border: 1px solid #334155;
            color: #34d399 !important;
            font-family: 'Courier New', Courier, monospace;
            padding: 20px;
            border-radius: 8px;
            max-height: 400px;
            overflow-y: auto;
            font-size: 0.95rem;
        }

        code {
            background-color: #0f172a;
            color: #10b981;
            padding: 4px 8px;
            border-radius: 4px;
            border: 1px solid #334155;
            font-family: 'Courier New', Courier, monospace;
        }

        .btn-outline-secondary {
            border-color: #334155;
            color: #94a3b8;
            transition: all 0.3s ease;
        }

        .btn-outline-secondary:hover {
            background-color: #334155;
            color: #f8fafc;
        }

        .btn-primary {
            background-color: #10b981;
            border-color: #10b981;
            color: #022c22;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s ease;
            border-radius: 8px;
            padding: 10px 20px;
        }

        .btn-primary:hover {
            background-color: #34d399;
            border-color: #34d399;
            color: #022c22;
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(16, 185, 129, 0.4);
        }

        /* Typography inside the guide */
        #encryption-guide h4 {
            color: #f8fafc;
            font-weight: 800;
            border-bottom: 1px solid #334155;
            padding-bottom: 1rem;
            margin-bottom: 1.5rem;
        }
        
        #encryption-guide h5 {
            color: #cbd5e1;
            font-size: 1.1rem;
            margin-top: 1.5rem;
            font-weight: 600;
        }
        
        #encryption-guide p, #encryption-guide li {
            color: #94a3b8;
            line-height: 1.7;
        }
    </style>
{% endblock %}

{% block content %}
<section>
    <div class="container">
        <div class="page-heading text-center mb-4">
            <h1>Indrajit's GPG Key</h1>
        </div>

        <!-- Link to encryption guide -->
        <div class="text-center mb-4">
            <a href="#encryption-guide" class="btn btn-sm btn-primary">
                🔐 Learn How to Send Me a Secret Message
            </a>
        </div>

        <div class="row justify-content-center">
            <div class="col-12 col-md-11 col-lg-10">
                <!-- GPG Key Card -->
                <div class="card mb-4 mx-auto">
                    <div class="card-body">
                        <h5 class="card-title">Key Fingerprint <i class="bi bi-fingerprint"></i></h5>
                        <div class="input-group mb-3">
                            <div id="fingerprint" class="form-control" style="overflow-x: auto; white-space: nowrap;" aria-label="Fingerprint">{{ fingerprint }}</div>
                            <button class="btn btn-outline-secondary" type="button" onclick="copyFingerprint()">
                                <i class="bi bi-clipboard"></i>
                            </button>
                        </div>

                        <h5 class="card-title">GPG Key <i class="bi bi-key-fill"></i></h5>
                        <div class="btn-group btn-group-sm mb-3" role="group" aria-label="Small button group">
                            <button type="button" class="btn btn-outline-secondary" onclick="copyGPGkey()">Copy</button>
                            <a class="btn btn-outline-secondary" href="{{ url_for('main.static', filename='keys/indrajit_gpg_public_key.asc') }}" download="indrajit_public_key.asc">Download</a>
                        </div>
                        <pre id="gpg-key-content" class="pre-scrollable">{{ gpg_key }}</pre>
                    </div>
                </div>

                <!-- GPG Message Encryption Guide -->
                <div id="encryption-guide" class="card mb-5 mx-auto">
                    <div class="card-body">
                        <h4 class="card-title">🔐 How to Send a Secret Message Using My GPG Key</h4>
                        <p>This step-by-step guide will show you how to encrypt a message using my public GPG key - without revealing any email.</p>

                        <h5>🛠 Prerequisites</h5>
                        <ul>
                            <li>Make sure <strong>GPG</strong> is installed. <a href="https://gnupg.org/download/" target="_blank">Download it here</a> if needed.</li>
                        </ul>

                        <h5>📥 Step 1: Get the GPG Key</h5>
                        <ol>
                            <li>Use the copy/download buttons above to get the key.</li>
                            <li>Save it in a file, e.g., <code>indrajit_gpg_key.txt</code>.</li>
                        </ol>

                        <h5>🔑 Step 2: Import the Key</h5>
                        <pre><code>gpg --import indrajit_gpg_key.txt</code></pre>

                        <h5>🛡 Step 3: Verify the Key</h5>
                        <p>Run this command to list fingerprints of all imported keys:</p>
                        <pre><code>gpg --fingerprint</code></pre>
                        <p>Now manually compare the fingerprint shown in your terminal with the one displayed above on this page. They should match <strong>exactly</strong>.</p>

                        <h5>📝 Step 4: Write Your Message</h5>
                        <p>Create your message in a file like <code>message.txt</code>. It can be any file format - text, PDF, etc.</p>

                        <h5>🔒 Step 5: Encrypt the Message</h5>
                        <p>Use the fingerprint from above in the command:</p>
                        <pre><code>gpg --output message.txt.gpg --encrypt --recipient {{ "".join(fingerprint.split()) }} message.txt</code></pre>
                        <p>This creates an encrypted file: <code>message.txt.gpg</code></p>

                        <h5>📤 Step 6: Send It</h5>
                        <p>Send <code>message.txt.gpg</code> to me via email, chat, or any preferred channel.</p>

                        <h5>🗑 Optional: Remove the Key</h5>
                        <pre><code>gpg --delete-key {{ "".join(fingerprint.split()) }}</code></pre>

                        <p class="mt-4">That's it! Your message will be secure, and I'll be able to decrypt it on my end. 🕵️‍♂️</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- Script for copying fingerprint and GPG key to clipboard -->
<script>
    function fallbackCopyTextToClipboard(text) {
        var textArea = document.createElement("textarea");
        textArea.value = text;
        
        // Avoid scrolling to bottom
        textArea.style.top = "0";
        textArea.style.left = "0";
        textArea.style.position = "fixed";

        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();

        try {
            var successful = document.execCommand('copy');
            if (successful) {
                alert("Copied to clipboard!");
            } else {
                console.error('Fallback: Copying text command was unsuccessful');
            }
        } catch (err) {
            console.error('Fallback: Oops, unable to copy', err);
        }

        document.body.removeChild(textArea);
    }

    function copyFingerprint() {
        var fingerprintText = document.getElementById('fingerprint').innerText.trim();
        if (!navigator.clipboard) {
            fallbackCopyTextToClipboard(fingerprintText);
            return;
        }
        navigator.clipboard.writeText(fingerprintText)
            .then(() => {
                alert("Copied the fingerprint to clipboard!");
            })
            .catch(err => {
                console.error('Failed to copy: ', err);
                fallbackCopyTextToClipboard(fingerprintText);
            });
    }

    function copyGPGkey() {
        var gpgKeyText = document.getElementById('gpg-key-content').innerText.trim();
        if (!navigator.clipboard) {
            fallbackCopyTextToClipboard(gpgKeyText);
            return;
        }
        navigator.clipboard.writeText(gpgKeyText)
            .then(() => {
                alert("Copied the GPG key to clipboard!");
            })
            .catch(err => {
                console.error('Failed to copy: ', err);
                fallbackCopyTextToClipboard(gpgKeyText);
            });
    }
</script>
{% endblock %}
'''

with open(r'C:\Users\indra\Documents\hello_world\PersonalWebsite\app\main\templates\gpgkey.html', 'w', encoding='utf-8') as f:
    f.write(new_content)
