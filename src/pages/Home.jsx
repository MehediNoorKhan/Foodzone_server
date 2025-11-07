import React from 'react';
import '../styles.css';
import Navbar from '../Components/Navbar';
import Hero from '../Components/Hero';
import About from '../Components/About';
import Skills from '../Components/Skills';
import Projects from '../Components/Projects';
import Testimonials from '../Components/Testimonials';
import Contact from '../Components/Contact';
import Footer from '../Components/Footer';
import Education from '../Components/Education';

const Home = () => {
    return (
        <div className='bg-gradient-to-br from-[#ffffff] via-[#e6f4ff] via-[#cce9ff] via-[#e6f4ff] to-[#ffffff]'>
            <Navbar></Navbar>
            <Hero></Hero>
            <About></About>
            <Education></Education>
            <Skills></Skills>
            <Projects></Projects>
            <Testimonials></Testimonials>
            <Contact></Contact>
            <Footer></Footer>
        </div>
    );
};

export default Home;