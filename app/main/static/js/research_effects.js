/**
 * research_effects.js
 * 
 * Injects subtle mathematical symbols into the background of the research page.
 * Respects prefers-reduced-motion to accommodate accessibility standards.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Configurable opacity for the background symbols (0.0 to 1.0)
    const backgroundOpacity = 0.22;
    document.documentElement.style.setProperty('--math-opacity', backgroundOpacity);

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // 1. Equations specifically from your research
    const equations = [
        String.raw`\(\mathrm{d}_{\textrm{KK}}(u\Delta u^*,v\Delta v^*)=\sin\alpha(u\Delta u^*,v\Delta v^*)\)`,
        String.raw`\(e^u e^v = (u\otimes\bar{u}) \left(e^{\mathbb{I}_n}e^{u^*v}\right) (u\otimes\bar{u})^*\)`,
        String.raw`\(\cos\alpha\left(u\Delta^{(n)}u^*,v\Delta^{(n)}v^*\right) = \frac{n}{n-1} \left\| \left[ |u^*v|^{\circ 2}\circ(u^*v) -\frac{1}{n}u^*v \right] \right\|_{\mathrm{op}}\)`,
        String.raw`\(\Phi_{\textrm{aff}}(S^{\textbf{Fr}})=\Phi_{\textrm{aff}}(S)^{\textbf{Fr}}\)`,
        String.raw`\(\sum_{i=1}^{l} \Lambda_{ij} \leq 1\)`,
        String.raw`\(P_{\vec{n}}^{\vec{d}}(x_1, x_2, \dots, x_l) := \prod_{j=1}^k \left( x_1^{d_j} + x_2^{d_j} + \dots + x_l^{d_j} \right)\)`,
        // String.raw`\(u = \begin{pmatrix} \frac{1}{\sqrt{3}} & \frac{1}{\sqrt{2}} & \frac{1}{\sqrt{6}} \\ \frac{1}{\sqrt{3}} & -\frac{1}{\sqrt{2}} & \frac{1}{\sqrt{6}} \\ \frac{1}{\sqrt{3}} & 0 & -\frac{2}{\sqrt{6}} \end{pmatrix}\)`,

        String.raw`\(\mathscr{M}_{\textrm{aff}}^{\textrm{MvN}} = \mathscr{M}_{\textrm{aff}}^{c}\)`,
        String.raw`\(\Phi_{\textrm{aff}}(T_1 + T_2) = \Phi_{\textrm{aff}}(T_1) + \Phi_{\textrm{aff}}(T_2)\)`,
        String.raw`\(\Phi_{\textrm{aff}}(T_1 T_2) = \Phi_{\textrm{aff}}(T_1) \Phi_{\textrm{aff}}(T_2)\)`,
        String.raw`\(\mathrm{dom} \big( \Phi_{\textrm{aff}}(T) \big) = \Phi_{\textrm{aff}}^s \big( \mathrm{dom} (T) \big)\)`,
        String.raw`\((A/B)^* = (B^*)^\dagger A^*\)`,
        String.raw`\(\textrm{Graph}\left(\Phi_{\textrm{aff}}(T)\right) = (\Phi_{(2)})^{s}_{\textrm{aff}} \left( \textrm{Graph}(T) \right)\)`
    ];

    // 2. Generic symbols from Operator Algebras
    const symbols = [
        String.raw`\(\mathscr{M}\)`,
        String.raw`\(\int f \, d\mu\)`,
        String.raw`\(L^\infty(\Omega, \mu)\)`,
        String.raw`\(\mathbb{C}^n\)`,
        String.raw`\(\mathcal{B}(\mathcal{H})\)`,
        String.raw`\(C^*\)`,
        String.raw`\(W^*\)`,
        String.raw`\(\sigma(T)\)`,
        String.raw`\(\lambda\)`,
        String.raw`\(\otimes\)`,
        String.raw`\(\oplus\)`,
        String.raw`\(\tau\)`
    ];

    // Combine both lists so every item appears exactly once on screen (no repetition)
    const items = [...equations, ...symbols];

    // Shuffle items to randomize the layout each time the page loads
    items.sort(() => Math.random() - 0.5);

    const bgContainer = document.createElement('div');
    bgContainer.id = 'math-background';
    bgContainer.setAttribute('aria-hidden', 'true');
    document.body.appendChild(bgContainer);

    // Responsive adjustments for mobile
    const isMobile = window.innerWidth < 768;
    const numCols = isMobile ? 1 : 3;
    
    // Render fewer items on mobile to guarantee large vertical gaps and prevent overlap
    const numSpans = isMobile ? Math.min(8, items.length) : items.length; 
    const duration = 65; // Slower, elegant floating for dense layout

    for (let i = 0; i < numSpans; i++) {
        const span = document.createElement('span');
        span.className = 'math-symbol';
        
        // Pick the exact item from the shuffled array (no Math.random() here)
        span.innerHTML = items[i];
        
        // Distribute uniformly across columns to prevent X-overlap
        const col = i % numCols;
        const colWidth = 80 / numCols;
        const baseLeft = col * colWidth; 
        
        // Give some random wiggle room, a bit more on mobile since it's only 1 column
        const wiggle = isMobile ? 15 : 5;
        span.style.left = `${baseLeft + Math.random() * wiggle + 2}vw`;
        
        // Make font size slightly smaller on mobile to prevent horizontal overflow
        const fontSizeOffset = isMobile ? 0.9 : 1.2;
        const size = Math.random() * 0.4 + fontSizeOffset; 
        span.style.fontSize = `${size}rem`;

        if (prefersReducedMotion) {
            span.style.transform = `translateY(${Math.random() * 90 + 5}vh) rotate(${Math.random() * 4 - 2}deg)`;
            span.style.opacity = backgroundOpacity;
            span.style.animation = 'none';
        } else {
            span.style.animationDuration = `${duration}s`;
            
            // Stagger the animation delays perfectly evenly so they are spaced vertically
            const delay = -(i * (duration / numSpans));
            span.style.animationDelay = `${delay}s`;
        }

        bgContainer.appendChild(span);
    }

    // Tell MathJax to typeset the newly injected equations
    if (window.MathJax && window.MathJax.Hub) {
        MathJax.Hub.Queue(["Typeset", MathJax.Hub, bgContainer]);
    }
});
