import { motion } from "framer-motion";
import { skills } from "../data/skills";

const Skills = () => {
    return (
        <section id="skills" className="py-12 bg-white">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                {/* Heading */}
                <h2
                    className="text-3xl sm:text-4xl md:text-5xl mb-8 text-center pb-2 font-bold bg-gradient-to-r from-[#4ade80] via-[#3b82f6] to-[#a78bfa] bg-clip-text text-transparent"
                    style={{ backgroundSize: "14% auto" }}
                >
                    Skills
                </h2>

                {/* Skills Grid */}
                <motion.div
                    className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6"
                    initial="hidden"
                    whileInView="visible"
                    viewport={{ once: true }}
                    transition={{ staggerChildren: 0.1 }}
                >
                    {skills.map(({ id, icon: Icon, title, description, bg }) => (
                        <motion.div
                            key={id}
                            className="flex flex-col items-center justify-center p-4 sm:p-5 rounded-lg shadow-md text-center cursor-pointer"
                            style={{
                                background: "linear-gradient(135deg, #FAF7FF, #F2EBFF, #E8DFFF)",
                            }}
                            initial={{ opacity: 0, y: 20 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            whileHover={{ scale: 1.05 }}
                            transition={{ type: "spring", stiffness: 80, damping: 15 }}
                        >
                            {/* Icon */}
                            <motion.div
                                className="p-3 sm:p-4 mb-2 rounded-full flex items-center justify-center"
                                whileHover={{ rotate: 35 }}
                                transition={{ type: "spring", stiffness: 80, damping: 15 }}
                                style={{
                                    backgroundColor: bg,
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center",
                                }}
                            >
                                <Icon size={28} className="sm:text-2xl text-white" />
                            </motion.div>

                            {/* Title */}
                            <h3 className="text-gray-800 font-semibold text-base sm:text-lg">
                                {title}
                            </h3>
                            {/* Description */}
                            <p className="text-gray-600 text-xs sm:text-sm">{description}</p>
                        </motion.div>
                    ))}
                </motion.div>
            </div>
        </section>
    );
};

export default Skills;
