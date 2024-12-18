let slideIndex = 0;
let slides = document.getElementsByClassName("mySlides");
let timer;

//has the fist image show up whenever the window is opened
window.onload = function(){
    showSlides(slideIndex);    
}

// Next/previous controls
function plusSlides(n) {
    showSlides(slideIndex += n);
}
  
// Thumbnail image controls
function currentSlide(n) {
    showSlides(slideIndex = n);
}

// Function to show slides
function showSlides(n) {
    if (n >= slides.length) { slideIndex = 0; }
    if (n < 0) { slideIndex = slides.length - 1; }
    
    for (let i = 0; i < slides.length; i++) {
        slides[i].style.display = "none";
    }

    slides[slideIndex].style.display = "block";
    //reset the timer on each new image
    clearTimeout(timer);
    timer = setTimeout(() => changeSlide(1), 10000); // Change every 10 seconds
}

// Function to change slide with buttons
function changeSlide(n) {
    slideIndex += n;
    showSlides(slideIndex);
}
