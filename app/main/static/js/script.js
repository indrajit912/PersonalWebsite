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
