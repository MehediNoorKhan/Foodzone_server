import { motion } from "framer-motion";
import { FaAward, FaProjectDiagram, FaUsers, FaClock } from "react-icons/fa";

const About = () => {
    const buttonGradient = "linear-gradient(to right, #4ade80, #3b82f6, #a78bfa)";

    const features = [
        { icon: FaProjectDiagram, title: "Projects Done", value: "12", bg: "bg-blue-400" },
        { icon: FaUsers, title: "Clients", value: "2", bg: "bg-pink-400" },
        { icon: FaAward, title: "Awards Won", value: "4", bg: "bg-purple-400" },
        { icon: FaClock, title: "Years of Experience", value: "1", bg: "bg-green-400" },
    ];

    return (
        <section id="about" className="px-4 sm:px-6 md:px-12 py-12 md:py-16 bg-white">
            <h2
                className="text-3xl sm:text-4xl md:text-5xl mb-10 text-center pb-2 font-bold bg-gradient-to-r from-[#4ade80] via-[#3b82f6] to-[#a78bfa] bg-clip-text text-transparent"
                style={{ backgroundSize: "13% auto" }}
            >
                About
            </h2>

            <div className="max-w-4xl mx-auto flex flex-col md:flex-row items-center gap-10 md:gap-12 font-sans">
                {/* Left Text */}
                <motion.div
                    initial={{ opacity: 0, y: 50 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8 }}
                    className="flex-1 text-base sm:text-lg md:text-xl leading-relaxed text-center md:text-left"
                >
                    <p className="mb-6 sm:mb-8 text-gray-600">
                        I'm <span className="text-pink-500 font-semibold">Mehedi Noor Khan</span>, a passionate{" "}
                        <span className="text-purple-500 font-semibold">Full Stack Web Developer</span>. I specialize in building
                        responsive, modern, and user-friendly web applications. I focus on clean, maintainable code and love solving
                        complex problems.
                    </p>

                    <div className="flex gap-3 sm:gap-4 justify-center md:justify-start flex-wrap">
                        <motion.a
                            href="https://drive.google.com/file/d/1HLkFtSUh6LWZ1in4BuLwQSMJO1g8WPO4/view?usp=sharing"
                            target="_blank"
                            rel="noreferrer"
                            whileHover={{ scale: 1.05 }}
                            className="px-4 sm:px-5 py-2 sm:py-3 rounded-md text-white font-semibold transition-transform shadow-lg text-sm sm:text-base"
                            style={{
                                background: buttonGradient,
                                boxShadow: "0 0 16px rgba(60, 130, 246, 0.6)",
                            }}
                        >
                            Download CV
                        </motion.a>
                        <motion.a
                            whileHover={{ scale: 1.05 }}
                            className="px-4 sm:px-5 py-2 sm:py-3 rounded-md text-white font-semibold transition-transform shadow-lg text-sm sm:text-base"
                            style={{
                                background: buttonGradient,
                                boxShadow: "0 0 16px rgba(60, 130, 246, 0.6)",
                            }}
                        >
                            <a
                                href="#projects"

                            >Hire Me</a>

                        </motion.a>

                    </div>
                </motion.div>

                {/* Right Features */}
                <motion.div className="flex-1 grid grid-cols-2 sm:grid-cols-2 gap-4 sm:gap-6">
                    {features.map((feature, index) => {
                        const Icon = feature.icon;
                        return (
                            <motion.div
                                key={index}
                                className="flex flex-col items-center text-center"
                                initial={{ opacity: 0, y: 20 }}
                                whileInView={{ opacity: 1, y: 0 }}
                                transition={{ duration: 0.5, delay: index * 0.1 }}
                            >
                                <motion.div
                                    className={`mb-1.5 p-3 sm:p-4 rounded-full ${feature.bg} text-white text-2xl flex items-center justify-center`}
                                    whileHover={{ scale: 1.1 }}
                                    transition={{ duration: 0.15 }}
                                >
                                    <Icon />
                                </motion.div>
                                <h3 className="text-sm sm:text-base font-semibold text-gray-700">{feature.title}</h3>
                                <p className="text-base sm:text-lg font-bold text-gray-500">{feature.value}</p>
                            </motion.div>
                        );
                    })}
                </motion.div>
            </div>
        </section>
    );
};

export default About;
