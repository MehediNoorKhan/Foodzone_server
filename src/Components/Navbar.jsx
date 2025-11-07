import { useState, useEffect } from "react";
import { Link } from "react-scroll";
import { FaBars, FaTimes } from "react-icons/fa";
import "../styles.css";

const Navbar = () => {
    const [navOpen, setNavOpen] = useState(false);
    const [scrolled, setScrolled] = useState(false);

    const links = [
        { id: 1, link: "home" },
        { id: 2, link: "about" },
        { id: 3, link: "education" },
        { id: 4, link: "skills" },
        { id: 5, link: "projects" },
        { id: 6, link: "testimonials" },
        { id: 7, link: "contacts" },
    ];

    useEffect(() => {
        const handleScroll = () => setScrolled(window.scrollY > 50);
        window.addEventListener("scroll", handleScroll);
        return () => window.removeEventListener("scroll", handleScroll);
    }, []);

    const buttonGradient = "linear-gradient(to right, #4ade80, #3b82f6, #a78bfa)";

    return (
        <div
            className={`fixed w-full z-50 backdrop-blur-lg transition-all duration-500 ${scrolled ? "shadow-md" : ""
                }`}
            style={{
                background: scrolled ? "white" : "",
            }}
        >
            <div className="flex justify-between items-center px-4 sm:px-6 md:px-10 py-4 max-w-7xl mx-auto">
                {/* Logo */}
                <h1 className="text-2xl sm:text-3xl font-bold text-gray-500">Mehedi</h1>

                {/* Desktop Menu */}
                <ul className="hidden md:flex space-x-6 lg:space-x-8 items-center">
                    {links.map(({ id, link }) => (
                        <li key={id} className="cursor-pointer capitalize">
                            <Link
                                to={link}
                                smooth
                                duration={500}
                                offset={-70}
                                className="gradient-underline text-gray-500 hover:text-gray-800"
                            >
                                {link}
                            </Link>
                        </li>
                    ))}
                </ul>

                {/* Hire Me Button (Desktop) */}
                <div className="hidden md:flex items-center">
                    <Link
                        to="contacts"
                        smooth
                        duration={500}
                        offset={-70}
                        className="px-4 py-2 rounded-md text-white cursor-pointer font-medium transform transition-transform duration-300 hover:scale-110 shadow-md"
                        style={{ background: buttonGradient }}
                    >
                        Hire Me
                    </Link>
                </div>

                {/* Mobile Menu Button */}
                <div
                    className="md:hidden cursor-pointer text-gray-500"
                    onClick={() => setNavOpen(!navOpen)}
                >
                    {navOpen ? <FaTimes size={24} /> : <FaBars size={24} />}
                </div>
            </div>

            {/* Mobile Menu */}
            {navOpen && (
                <ul className="md:hidden absolute w-full flex flex-col items-center py-6 space-y-4 bg-white shadow-md">
                    {links.map(({ id, link }) => (
                        <li
                            key={id}
                            className="capitalize text-lg text-gray-500 hover:text-gray-700"
                            onClick={() => setNavOpen(false)}
                        >
                            <Link to={link} smooth duration={500} offset={-70}>
                                {link}
                            </Link>
                        </li>
                    ))}
                    <li className="w-full flex justify-center">
                        <Link
                            to="contacts"       // Matches your section id
                            smooth
                            duration={500}
                            offset={-70}         // Adjusts scroll offset for fixed navbar
                            className="px-4 py-2 rounded-md text-white cursor-pointer font-medium transition-all duration-300 shadow-md"
                            style={{ background: buttonGradient }}
                            onClick={() => setNavOpen(false)}
                        >
                            Hire Me
                        </Link>
                    </li>

                </ul>
            )}
        </div>
    );
};

export default Navbar;
