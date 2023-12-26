// Add this to your existing JavaScript or create a new JS file
window.onscroll = function () {
    scrollFunction();
};

function scrollFunction() {
    var scrollBtn = document.getElementById("scrollUpBtn");

    // Display the button when the user scrolls down 600 pixels
    if (document.body.scrollTop > 1000 || document.documentElement.scrollTop > 1000) {
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
