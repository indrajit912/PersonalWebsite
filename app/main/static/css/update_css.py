import sys

with open(r'C:\Users\indra\Documents\hello_world\PersonalWebsite\app\main\static\css\style.css', 'r', encoding='utf-8') as f:
    content = f.read()

math_css = '''
/* ---------------------------------
   Math Background Global Effect
-----------------------------------*/
#math-background {
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    pointer-events: none;
    z-index: -1; 
    overflow: hidden;
    background-color: var(--color-white, #ffffff);
}

.math-symbol {
    position: absolute;
    color: var(--color-dark, #2c3e50);
    opacity: var(--math-opacity, 0.15);
    white-space: nowrap;
    user-select: none;
    font-family: "Georgia", serif;
    animation: floatUp linear infinite;
    transform: translateY(130vh);
}

@keyframes floatUp {
    0% {
        transform: translateY(130vh) rotate(0deg);
        opacity: 0;
    }
    10% {
        opacity: var(--math-opacity, 0.15);
    }
    90% {
        opacity: var(--math-opacity, 0.15);
    }
    100% {
        transform: translateY(-30vh) rotate(5deg);
        opacity: 0;
    }
}
'''

index_css = '''
/* -------------------------------
   Index Page Effects
--------------------------------*/
.cursor {
    display: inline-block;
    width: 3px;
    background-color: var(--accent-color, #2c3e50);
    margin-left: 4px;
    animation: blink 1s infinite;
}
.cursor.typing {
    animation: none;
}
@keyframes blink {
    0% { background-color: transparent; }
    50% { background-color: var(--accent-color, #2c3e50); }
    100% { background-color: transparent; }
}

.reveal {
    opacity: 0;
    transform: translateY(40px);
    transition: all 0.8s cubic-bezier(0.5, 0, 0, 1);
}
.reveal.active {
    opacity: 1;
    transform: translateY(0);
}

/* Subtle glow behind the profile picture */
.header-left .profile-pic {
    box-shadow: 0 0 40px rgba(44, 62, 80, 0.15);
    transition: transform 0.4s ease, box-shadow 0.4s ease;
}
.header-left .profile-pic:hover {
    transform: scale(1.03);
    box-shadow: 0 0 60px rgba(44, 62, 80, 0.25);
}

/* Header buttons hover effect enhancement */
.header-action-area .indra-btn {
    transition: transform 0.3s ease, box-shadow 0.3s ease, background-color 0.3s ease;
}
.header-action-area .indra-btn:hover {
    transform: translateY(-3px);
    box-shadow: 0 6px 15px rgba(0,0,0,0.1);
}
'''

contact_css = '''/* ........................ Start Contact Form Styles ...................... */
.contact-form {
    display: flex;
    align-items: center;
    justify-content: center;
    margin-top: 3rem;
    margin-bottom: 4rem;
}

.contact-form form {
    position: relative;
    width: 650px;
    background: #ffffff;
    padding: 40px;
    border-radius: 16px;
    box-shadow: 0 15px 35px rgba(0, 0, 0, 0.08);
    border: 1px solid rgba(0, 0, 0, 0.03);
}

.custom-input,
.msg-input {
    width: 100%;
    padding: 16px 20px;
    border: 2px solid #e1e5ee;
    outline: none;
    background: #f8fafc;
    color: #333;
    margin-bottom: 20px;
    border-radius: 10px;
    font-size: 16px;
    transition: all 0.3s ease;
    font-family: inherit;
}

.custom-input:focus,
.msg-input:focus {
    border-color: var(--color-dark, #2c3e50);
    background: #ffffff;
    box-shadow: 0 4px 15px rgba(44, 62, 80, 0.08);
}

.contact-form input::placeholder,
.contact-form textarea::placeholder {
    color: #94a3b8;
    font-size: 15px;
}

.contact-form textarea {
    resize: vertical;
    min-height: 150px;
}

/* Attachment styling */
#attachment-container {
    margin-bottom: 10px;
}

#attachment-container p {
    font-weight: 600;
    margin-bottom: 12px;
    color: #475569;
    font-size: 15px;
}

#attachment-container > div {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
    background: #f8fafc;
    border: 1px dashed #cbd5e1;
    padding: 10px;
    border-radius: 8px;
}

#attachment-container input[type="file"] {
    font-size: 14px;
    color: #64748b;
    width: 75%;
}

#attachment-container button {
    background-color: #ef4444;
    color: white;
    border: none;
    padding: 6px 12px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s ease;
}

#attachment-container button:hover {
    background-color: #dc2626;
}

#add-more-btn {
    background: transparent;
    color: var(--color-dark, #2c3e50);
    border: 2px dashed #94a3b8;
    padding: 10px 16px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    margin-bottom: 25px;
    transition: all 0.2s ease;
    width: 100%;
}

#add-more-btn:hover {
    border-color: var(--color-dark, #2c3e50);
    background: rgba(44, 62, 80, 0.05);
}

.contact-form .send-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    padding: 14px 30px;
    background: var(--color-dark, #2c3e50);
    color: var(--color-white, #ffffff);
    border: none;
    border-radius: 10px;
    font-size: 16px;
    font-weight: 600;
    transition: all 0.3s ease;
    width: 100%;
    cursor: pointer;
    box-shadow: 0 6px 15px rgba(44, 62, 80, 0.2);
}

.contact-form .send-btn:hover {
    transform: translateY(-3px);
    box-shadow: 0 10px 25px rgba(44, 62, 80, 0.3);
}

@media(max-width: 786px) {
    .contact-form form {
        width: 100%;
        padding: 25px 20px;
        box-shadow: none;
        border: none;
        background: transparent;
    }
    
    #attachment-container > div {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
    }

    #attachment-container input[type="file"] {
        width: 100%;
    }
}
/* ........................ End Contact Form Styles ...................... */'''

# Replace contact CSS block
start_marker = '/* ........................ Start Contact Form Styles ...................... */'
end_marker = '/* ........................ End Contact Form Styles ...................... */'

start_idx = content.find(start_marker)
end_idx = content.find(end_marker)

if start_idx != -1 and end_idx != -1:
    end_idx += len(end_marker)
    content = content[:start_idx] + contact_css + content[end_idx:]
else:
    print('Error: Contact form markers not found.')
    sys.exit(1)

# Append math_css and index_css to the end of the file
content += "\n" + math_css + "\n" + index_css

with open(r'C:\Users\indra\Documents\hello_world\PersonalWebsite\app\main\static\css\style.css', 'w', encoding='utf-8') as f:
    f.write(content)

print('CSS fully restored and updated.')
