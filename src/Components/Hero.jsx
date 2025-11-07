import { motion } from "framer-motion";
import { FaGithub, FaLinkedin, FaFacebook } from "react-icons/fa";
import { TypeAnimation } from "react-type-animation";
import ProfileImage from "../../assets/forCv.jpg";
import "../styles.css";

const Hero = () => {
    const skills = [
        { name: "HTML5", gradient: "bg-gradient-to-r from-orange-400 via-red-400 to-pink-500" },
        { name: "CSS3", gradient: "bg-gradient-to-r from-blue-400 via-cyan-400 to-indigo-500" },
        { name: "JavaScript", gradient: "bg-gradient-to-r from-yellow-400 via-orange-400 to-red-500" },
        { name: "Tailwind", gradient: "bg-gradient-to-r from-teal-400 via-cyan-400 to-blue-500" },
        { name: "React", gradient: "bg-gradient-to-r from-sky-400 via-blue-400 to-indigo-500" },
        { name: "Nextjs", gradient: "bg-gradient-to-r from-gray-700 via-gray-900 to-black" },
    ];

    return (
        <section className="flex items-center">
            <div className="max-w-7xl mx-auto flex flex-col-reverse md:flex-row items-center justify-between px-4 sm:px-6 md:px-0 pt-20 sm:pt-28 pb-8 gap-8 md:gap-16">

                {/* Left Side: Text */}
                <div className="flex-1 text-center md:text-left space-y-4">
                    {/* Available for work */}
                    <motion.div
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.8 }}
                        className="flex items-center justify-center md:justify-start space-x-2 mb-2"
                    >
                        <span className="relative flex h-3 w-3">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-500 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-3 w-3 bg-blue-500"></span>
                        </span>
                        <span className="text-black text-sm font-medium">Available for work</span>
                    </motion.div>

                    {/* Greeting */}
                    <motion.h2
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.6, delay: 0.2 }}
                        className="text-xl sm:text-2xl font-bold text-gray-500"
                    >
                        Hi There! I am
                    </motion.h2>

                    {/* Name */}
                    <motion.h1
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.6, delay: 0.4 }}
                        className="text-3xl sm:text-4xl md:text-5xl font-bold bg-black bg-clip-text text-transparent drop-shadow-lg"
                    >
                        Mehedi Noor Khan
                    </motion.h1>

                    {/* Animated Role */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.6, duration: 0.6 }}
                        className="text-xl sm:text-2xl font-bold text-gray-500 mb-4"
                    >
                        I'm a{" "}
                        <TypeAnimation
                            sequence={["Frontend Developer", 2000, "React Enthusiast", 2000]}
                            wrapper="span"
                            cursor={true}
                            repeat={Infinity}
                            style={{ textShadow: "0 0 12px rgba(59, 130, 246, 0.9)" }}
                        />
                    </motion.div>

                    {/* Description */}
                    <motion.p
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.8, duration: 0.6 }}
                        className="text-gray-500 max-w-md mx-auto md:mx-0 text-sm sm:text-base"
                    >
                        I build responsive and modern web applications. Passionate about React and Next.js.
                        I love designing interactive UIs and learning new technologies.
                    </motion.p>

                    {/* Skills */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 1, duration: 0.6 }}
                        className="flex flex-wrap justify-center md:justify-start gap-2 md:gap-3 overflow-x-auto scrollbar-hide"
                    >
                        {skills.map((skill, idx) => (
                            <span
                                key={idx}
                                className={`px-3 py-1 rounded-full text-white text-sm sm:text-xs md:text-sm font-medium shadow-md ${skill.gradient} whitespace-nowrap`}
                            >
                                {skill.name}
                            </span>
                        ))}
                    </motion.div>

                    {/* Button */}
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 1.2, duration: 0.6 }}
                        className="pt-4 flex justify-center md:justify-start"
                    >
                        <a
                            href="#projects"
                            className="px-6 py-2 sm:py-3 rounded-md text-white font-semibold shadow-lg transform transition-transform duration-300 hover:scale-105 bg-gradient-to-r from-green-400 via-blue-400 to-purple-500 text-sm sm:text-base"
                        >
                            View My Work
                        </a>
                    </motion.div>

                    {/* Social Icons */}
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 1.4, duration: 0.6 }}
                        className="flex items-center justify-center md:justify-start gap-4 mt-4 sm:mt-6"
                    >
                        <a
                            href="https://github.com/yourusername"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-2 bg-gray-200 rounded-full shadow-md transition-all duration-500 hover:bg-white hover:scale-110"
                        >
                            <FaGithub className="text-gray-800 text-xl sm:text-2xl" />
                        </a>
                        <a
                            href="https://linkedin.com/in/yourusername"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-2 bg-gray-200 rounded-full shadow-md transition-all duration-500 hover:bg-white hover:scale-110"
                        >
                            <FaLinkedin className="text-[#0A66C2] text-xl sm:text-2xl" />
                        </a>
                        <a
                            href="https://facebook.com/yourusername"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-2 bg-gray-200 rounded-full shadow-md transition-all duration-500 hover:bg-white hover:scale-110"
                        >
                            <FaFacebook className="text-[#1877F2] text-xl sm:text-2xl" />
                        </a>
                    </motion.div>
                </div>

                {/* Right Side: Profile Image */}
                <motion.div
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 1.4, duration: 0.6 }}
                    className="flex-1 flex justify-center md:justify-end mb-6 md:mb-0"
                >
                    <div className="p-1 sm:p-1 md:p-1 rounded-full bg-blue-300">
                        <img
                            src={ProfileImage}
                            alt="Mehedi Noor Khan"
                            className="w-40 h-40 sm:w-56 sm:h-56 md:w-72 md:h-72 rounded-full object-cover"
                        />
                    </div>
                </motion.div>
            </div>
        </section>
    );
};

export default Hero;
