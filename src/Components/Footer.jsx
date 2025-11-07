import { FaGithub, FaLinkedin, FaFacebook } from "react-icons/fa";

const Footer = () => {
    return (
        <footer className="bg-gradient-to-r from-blue-600 to-purple-600 text-white py-8 shadow-lg">
            <div className="max-w-6xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center">
                <p className="mb-4 md:mb-0 text-center md:text-left">
                    &copy; {new Date().getFullYear()} Mehedi Noor Khan. All rights reserved.
                </p>
                <div className="flex space-x-6 text-2xl">
                    <a
                        href="https://github.com/MehediNoorKhan/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:text-gray-200 transition-colors duration-300"
                    >
                        <FaGithub />
                    </a>
                    <a
                        href="https://www.linkedin.com/in/mehedinoorkhan16/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:text-gray-200 transition-colors duration-300"
                    >
                        <FaLinkedin />
                    </a>
                    <a
                        href="https://www.facebook.com/mehedinoorkhan/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:text-gray-200 transition-colors duration-300"
                    >
                        <FaFacebook />
                    </a>
                </div>
            </div>
        </footer>
    );
};

export default Footer;
