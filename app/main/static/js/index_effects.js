/**
 * index_effects.js
 * 
 * Adds professional animations and interactivity to the index page,
 * including a typewriter effect for the roles and scroll-reveal animations.
 */
document.addEventListener('DOMContentLoaded', () => {
    // 1. Typewriter Effect for the header role
    const roles = [
        "Postdoctoral Researcher",
        "Operator Algebraist",
        "Python Developer",
        "Open Source Contributor"
    ];
    
    // We target the h3 element inside the header-right container
    const h3Element = document.querySelector('.header-right h3');
    
    if (h3Element) {
        let roleIndex = 0;
        let charIndex = 0;
        let isDeleting = false;
        let typingDelay = 100;
        
        // Wrap the content in a span for the text and a span for the cursor
        h3Element.innerHTML = '<span class="typed-text"></span><span class="cursor">|</span>';
        const textSpan = h3Element.querySelector('.typed-text');
        const cursorSpan = h3Element.querySelector('.cursor');

        function type() {
            const currentRole = roles[roleIndex];
            
            if (isDeleting) {
                textSpan.textContent = currentRole.substring(0, charIndex - 1);
                charIndex--;
                typingDelay = 50; // Deleting is faster
            } else {
                textSpan.textContent = currentRole.substring(0, charIndex + 1);
                charIndex++;
                typingDelay = 100; // Typing speed
            }
            
            cursorSpan.classList.add('typing');
            
            if (!isDeleting && charIndex === currentRole.length) {
                // Pause at the end of a word
                typingDelay = 2500;
                isDeleting = true;
                cursorSpan.classList.remove('typing');
            } else if (isDeleting && charIndex === 0) {
                isDeleting = false;
                roleIndex = (roleIndex + 1) % roles.length;
                typingDelay = 500; // Pause before typing next word
                cursorSpan.classList.remove('typing');
            }
            
            setTimeout(type, typingDelay);
        }
        
        // Start typing after a short delay
        setTimeout(type, 800);
    }

    // 2. Scroll Reveal Animation for the About Me section
    const revealElements = document.querySelectorAll('#about-me p, #about-me h1, #about-me .heading-p');
    
    // Add the reveal class to all target elements
    revealElements.forEach(el => {
        el.classList.add('reveal');
    });
    
    const revealOptions = {
        threshold: 0.15,
        rootMargin: "0px 0px -50px 0px"
    };
    
    const revealOnScroll = new IntersectionObserver(function(entries, observer) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
                observer.unobserve(entry.target); // Stop observing once revealed
            }
        });
    }, revealOptions);
    
    revealElements.forEach(el => {
        revealOnScroll.observe(el);
    });
});
