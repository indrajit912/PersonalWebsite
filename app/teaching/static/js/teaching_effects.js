/**
 * teaching_effects.js
 * 
 * Injects subtle, famous mathematical equations into the background of the teaching page.
 * Respects prefers-reduced-motion to accommodate accessibility standards.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Configurable opacity for the background symbols (0.0 to 1.0)
    const backgroundOpacity = 0.20;
    document.documentElement.style.setProperty('--math-opacity', backgroundOpacity);

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Famous equations for the teaching page
    const equations = [
        // Constants & Basics
        String.raw`\(e^{i\pi} + 1 = 0\)`,
        String.raw`\(a^2 + b^2 = c^2\)`,
        String.raw`\(A = \pi r^2\)`,
        
        // Calculus & Analysis
        String.raw`\(\int_a^b f(x) \, dx = F(b) - F(a)\)`,
        String.raw`\(f(x) = \sum_{n=0}^\infty \frac{f^{(n)}(a)}{n!} (x-a)^n\)`,
        String.raw`\(\lim_{x \to 0} \frac{\sin x}{x} = 1\)`,
        String.raw`\(\nabla \times \mathbf{F} = \operatorname{curl}(\mathbf{F})\)`,
        String.raw`\(\frac{\partial u}{\partial t} = \alpha \nabla^2 u\)`,
        String.raw`\(\frac{\partial^2 u}{\partial t^2} = c^2 \nabla^2 u\)`,
        
        // Algebra & Linear Algebra
        String.raw`\((x+y)^n = \sum_{k=0}^n \binom{n}{k} x^{n-k} y^k\)`,
        String.raw`\(p(\lambda) = \det(A - \lambda I)\)`,
        String.raw`\(A = Q \Lambda Q^{-1}\)`,
        String.raw`\(e^{At} = \sum_{n=0}^\infty \frac{t^n}{n!} A^n\)`,
        String.raw`\(|\langle u, v \rangle|^2 \leq \langle u, u \rangle \langle v, v \rangle\)`,
        String.raw`\(G / \ker \phi \cong \mathrm{im}\, \phi\)`,
        
        // Complex Analysis & Geometry
        String.raw`\(f(a) = \frac{1}{2\pi i} \oint_\gamma \frac{f(z)}{z-a} \, dz\)`,
        String.raw`\(\int_{\partial \Omega} \omega = \int_{\Omega} d\omega\)`,
        String.raw`\(V - E + F = 2\)`,
        String.raw`\(\frac{\partial u}{\partial x} = \frac{\partial v}{\partial y}, \quad \frac{\partial u}{\partial y} = -\frac{\partial v}{\partial x}\)`,
        
        // Physics (Quantum, Relativity, Classical, EM)
        String.raw`\(E = mc^2\)`,
        String.raw`\(i\hbar\frac{\partial}{\partial t}\Psi = \hat{H}\Psi\)`,
        String.raw`\((i\gamma^\mu\partial_\mu - m)\psi = 0\)`,
        String.raw`\(\Delta x \Delta p \geq \frac{\hbar}{2}\)`,
        String.raw`\(F = G \frac{m_1 m_2}{r^2}\)`,
        
        // Stat Mech & Probability
        String.raw`\(S = k \log W\)`,
        
        // Number Theory & Advanced Math
        String.raw`\(\zeta(s) = \sum_{n=1}^\infty \frac{1}{n^s}\)`,
        String.raw`\(\pi(x) \sim \frac{x}{\ln x}\)`,
        String.raw`\(a^{p-1} \equiv 1 \pmod p\)`,
        String.raw`\(\hat{f}(\xi) = \int_{-\infty}^\infty f(x) e^{-2\pi i x \xi} dx\)`,
        String.raw`\(\int_{-\infty}^\infty |f(x)|^2 dx = \int_{-\infty}^\infty |\hat{f}(\xi)|^2 d\xi\)`,
        String.raw`\(\mathrm{ind}(D) = \int_M \mathrm{ch}(V) \wedge \mathrm{Td}(M)\)`
    ];

    // Shuffle equations
    equations.sort(() => Math.random() - 0.5);

    const bgContainer = document.createElement('div');
    bgContainer.id = 'math-background';
    bgContainer.setAttribute('aria-hidden', 'true');
    document.body.appendChild(bgContainer);

    // Responsive adjustments for mobile
    const isMobile = window.innerWidth < 768;
    const numCols = isMobile ? 1 : 4;
    
    // Reduce number of spans significantly on mobile to prevent vertical stacking issues
    const numSpans = isMobile ? 12 : equations.length; 
    const duration = 120; // Much slower for dense equations to give a majestic feel

    for (let i = 0; i < numSpans; i++) {
        const span = document.createElement('span');
        span.className = 'math-symbol';
        
        span.innerHTML = equations[i];
        
        // Use multiple columns on desktop to pack more equations densely without total overlap
        const col = i % numCols;
        const colWidth = 80 / numCols; 
        const baseLeft = col * colWidth;
        
        const wiggle = isMobile ? 15 : 4;
        span.style.left = `${baseLeft + Math.random() * wiggle + 2}vw`;
        
        // Use a smaller font size on mobile to prevent wide equations from overflowing
        const fontSizeOffset = isMobile ? 0.7 : 1.0;
        const size = Math.random() * 0.5 + fontSizeOffset; 
        span.style.fontSize = `${size}rem`;

        if (prefersReducedMotion) {
            span.style.transform = `translateY(${Math.random() * 90 + 5}vh) rotate(${Math.random() * 4 - 2}deg)`;
            span.style.opacity = backgroundOpacity;
            span.style.animation = 'none';
        } else {
            span.style.animationDuration = `${duration}s`;
            const delay = -(i * (duration / numSpans));
            span.style.animationDelay = `${delay}s`;
        }

        bgContainer.appendChild(span);
    }

    if (window.MathJax && window.MathJax.Hub) {
        MathJax.Hub.Queue(["Typeset", MathJax.Hub, bgContainer]);
    }
});
