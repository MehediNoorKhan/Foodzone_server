import { motion } from "framer-motion";
import educationData from "../data/education.js";

const Education = () => {
    return (
        <section
            id="education"
            className="flex flex-col items-center px-4 sm:px-6 md:px-12 py-12"
        >
            {/* Heading */}
            <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold mb-10 sm:mb-12 text-center bg-gradient-to-r from-[#4ade80] via-[#3b82f6] to-[#a78bfa] bg-clip-text text-transparent">
                Education
            </h2>

            <div className="max-w-4xl w-full relative">
                {/* Vertical Bar */}
                <div className="absolute left-4 sm:left-5 top-0 w-1 h-full bg-blue-300 rounded-full"></div>

                <div className="space-y-8 sm:space-y-10">
                    {educationData.map((edu, index) => (
                        <motion.div
                            key={index}
                            initial={{ opacity: 0, y: 50 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.8, delay: index * 0.2 }}
                            className="relative pl-10 sm:pl-12 flex flex-col sm:flex-row items-start sm:items-center group"
                        >
                            {/* Circle marker */}
                            <span className="absolute left-0 mt-1 sm:mt-2 w-4 h-4 rounded-full bg-blue-400 group-hover:bg-blue-600 transition-colors duration-300"></span>

                            {/* Education Info */}
                            <div className="bg-white p-4 sm:p-6 rounded-xl shadow-lg w-full transition-all duration-500 group-hover:bg-blue-600">
                                <h3 className="text-lg sm:text-xl md:text-2xl font-bold text-gray-700 mb-1 group-hover:text-white transition-colors duration-300">
                                    {edu.degree}
                                </h3>
                                <p className="text-gray-600 font-medium mb-1 group-hover:text-white transition-colors duration-300">
                                    {edu.institution}
                                </p>
                                <p className="text-gray-500 text-sm sm:text-base group-hover:text-white transition-colors duration-300">
                                    {edu.duration}
                                </p>
                            </div>
                        </motion.div>
                    ))}
                </div>
            </div>
        </section>
    );
};

export default Education;
