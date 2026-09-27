// script.js
// Javascripts for the Website
// Author: Indrajit Ghosh
// Created On: Dec 26, 2023
// 

// Javascript to open the sidebar
function showSidebar(){
    const sidebar = document.querySelector('.sidebar')
    sidebar.style.display = 'flex'
}

function hideSidebar(){
    const sidebar = document.querySelector('.sidebar')
    sidebar.style.display = 'none'
}

// Javascript for scroll up button
window.onscroll = function () {
    scrollFunction();
};

function scrollFunction() {
    var scrollBtn = document.getElementById("scrollUpBtn");

    // Display the button when the user scrolls down 650 pixels
    if (document.body.scrollTop > 650 || document.documentElement.scrollTop > 650) {
        scrollBtn.style.display = "block";
    } else {
        scrollBtn.style.display = "none";
    }
}

function scrollToTop() {
    // Smooth scrolling to the top of the page
    document.body.scrollTop = 0;
    document.documentElement.scrollTop = 0;
}


// Dynamic Random Quotes for Pages
const quotesDB = {
    teaching: [
        { q: "I cannot teach anybody anything. I can only make them think.", a: "Socrates" },
        { q: "The art of teaching is the art of assisting discovery.", a: "Mark Van Doren" },
        { q: "Education is not the learning of facts, but the training of the mind to think.", a: "Albert Einstein" },
        { q: "The good teacher explains. The superior teacher demonstrates. The great teacher inspires.", a: "William Arthur Ward" },
        { q: "To teach is to learn twice.", a: "Joseph Joubert" }
    ],
    research: [
        { q: "A mathematician, like a painter or a poet, is a maker of patterns. If his patterns are more permanent than theirs, it is because they are made with ideas.", a: "G. H. Hardy" },
        { q: "Mathematics is the art of giving the same name to different things.", a: "Henri Poincaré" },
        { q: "Pure mathematics is, in its way, the poetry of logical ideas.", a: "Albert Einstein" },
        { q: "There is no branch of mathematics, however abstract, which may not some day be applied to phenomena of the real world.", a: "Nikolai Lobachevsky" },
        { q: "The essence of mathematics lies in its freedom.", a: "Georg Cantor" }
    ],
    cooking: [
        { q: "One cannot think well, love well, sleep well, if one has not dined well.", a: "Virginia Woolf" },
        { q: "People who love to eat are always the best people.", a: "Julia Child" },
        { q: "Cooking is like love. It should be entered into with abandon or not at all.", a: "Harriet Van Horne" },
        { q: "A recipe has no soul. You, as the cook, must bring soul to the recipe.", a: "Thomas Keller" },
        { q: "First we eat, then we do everything else.", a: "M.F.K. Fisher" }
    ],
    photos: [
        { q: "To photograph is to hold one's breath, when all faculties converge to capture fleeting reality.", a: "Henri Cartier-Bresson" },
        { q: "You don't take a photograph, you make it.", a: "Ansel Adams" },
        { q: "Photography is the story I fail to put into words.", a: "Destin Sparks" },
        { q: "A good photograph is knowing where to stand.", a: "Ansel Adams" },
        { q: "What I like about photographs is that they capture a moment that's gone forever.", a: "Karl Lagerfeld" }
    ]
};

document.addEventListener("DOMContentLoaded", function() {
    let path = window.location.pathname.toLowerCase();
    let category = null;
    
    if (path.includes('teaching') || path.includes('mth')) category = 'teaching';
    else if (path.includes('research')) category = 'research';
    else if (path.includes('cooking')) category = 'cooking';
    else if (path.includes('photo')) category = 'photos';

    if (category) {
        let quoteBlocks = document.querySelectorAll('.page-quote');
        if (quoteBlocks.length > 0) {
            let list = quotesDB[category];
            let randomQuote = list[Math.floor(Math.random() * list.length)];
            
            quoteBlocks.forEach(block => {
                block.innerHTML = randomQuote.q + " <footer>" + randomQuote.a + "</footer>";
            });
        }
    }
});
