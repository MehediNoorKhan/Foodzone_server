import { FaExternalLinkAlt, FaGithub } from "react-icons/fa";
import { projects } from "../data/projects.js";
import { motion } from "framer-motion";

// Diverse hex-based badge gradients
const techGradients = {
    HTML: { gradient: ["#FFD6D6", "#FF9A9A", "#FF4C4C"], text: "#7F1D1D" },
    CSS: { gradient: ["#D6E4FF", "#85A5FF", "#3366FF"], text: "#0B3D91" },
    Bootstrap: { gradient: ["#FFE0F0", "#FF99CC", "#FF33AA"], text: "#8B0F5D" },
    JavaScript: { gradient: ["#FFF7D6", "#FFE066", "#FFCC00"], text: "#7F6000" },
    "Next.js": { gradient: ["#E6D6FF", "#C299FF", "#9933FF"], text: "#4B0082" },
    MySQL: { gradient: ["#D6FFF0", "#66FFD9", "#00FFB3"], text: "#007F56" },
    "Framer-Motion": { gradient: ["#FFDEE9", "#B5FFFC", "#FFC6FF"], text: "#6B21A8" },
    Prisma: { gradient: ["#D6F0FF", "#66D9FF", "#00B3FF"], text: "#004F7F" },
    "React.js": { gradient: ["#E6FFE6", "#99FF99", "#33CC33"], text: "#0D660D" },
    "Node.js": { gradient: ["#FFF0D6", "#FFB366", "#FF8000"], text: "#7F3D00" },
    "Express.js": { gradient: ["#F0F0D6", "#D9D966", "#B3B300"], text: "#4F4F00" },
    MongoDB: { gradient: ["#D6FFE6", "#66FFB3", "#00FF66"], text: "#007F33" },
    "Tailwind CSS": { gradient: ["#F0D6FF", "#D966FF", "#B300FF"], text: "#4B0082" },
    Axios: { gradient: ["#D6E0FF", "#6699FF", "#0033FF"], text: "#001F7F" },
    "Firebase Auth": { gradient: ["#FFF0D6", "#FFCC66", "#FF9900"], text: "#7F4F00" },
    Stripe: { gradient: ["#D6F0FF", "#66CCFF", "#0099FF"], text: "#004F7F" },
};

const Projects = () => {
    return (
        <section id="projects" className="py-16">
            <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
                {/* Heading */}
                <h2
                    className="text-4xl md:text-5xl font-bold mb-4 text-center pb-2 bg-gradient-to-r from-[#4ade80] via-[#3b82f6] to-[#a78bfa] bg-clip-text text-transparent"
                    style={{ backgroundSize: "20% auto" }}
                >
                    Projects
                </h2>
                <p className="text-gray-600 text-center mb-12">
                    Some of my recent projects are displayed below.
                </p>

                {/* Project Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8">
                    {projects.map(
                        ({ id, title, image, link, github, technologies, description }) => (
                            <motion.div
                                key={id}
                                initial={{ opacity: 0, y: 50 }}
                                whileInView={{ opacity: 1, y: 0 }}
                                viewport={{ once: true }}
                                transition={{ duration: 0.6, ease: "easeOut" }}
                                whileHover={{ scale: 1.05 }}
                                className="relative flex flex-col h-full sm:h-[480px] bg-white rounded-xl shadow-md overflow-hidden transition-shadow duration-300 hover:shadow-xl"
                            >
                                {/* Project Image */}
                                <figure className="h-40 overflow-hidden">
                                    <img
                                        src={image}
                                        alt={title}
                                        className="w-full h-full object-cover transition-transform duration-300 hover:scale-105"
                                    />
                                </figure>

                                {/* Card Body */}
                                <div className="flex flex-col flex-1 p-4 sm:p-6 text-left relative">
                                    {/* Tech Badges */}
                                    <div className="flex flex-wrap gap-2 mb-2">
                                        {technologies.map((tech, index) => {
                                            const gradient =
                                                techGradients[tech]?.gradient || [
                                                    "#E5E7EB",
                                                    "#D1D5DB",
                                                    "#9CA3AF",
                                                ];
                                            const textColor = techGradients[tech]?.text || "#374151";

                                            return (
                                                <motion.span
                                                    key={index}
                                                    className="text-xs sm:text-sm font-semibold px-3 py-1 rounded-full cursor-pointer"
                                                    style={{
                                                        background: `linear-gradient(90deg, ${gradient[0]}, ${gradient[1]}, ${gradient[2]})`,
                                                        color: textColor,
                                                    }}
                                                    whileHover={{ scale: 1.1, rotate: 5 }}
                                                    transition={{ type: "spring", stiffness: 200, damping: 10 }}
                                                >
                                                    {tech}
                                                </motion.span>
                                            );
                                        })}
                                    </div>

                                    {/* Title */}
                                    <h3 className="text-lg sm:text-xl font-bold mb-2">{title}</h3>

                                    {/* Description */}
                                    <div className="relative flex-1 group">
                                        <p
                                            className="text-gray-700 overflow-hidden text-ellipsis text-sm sm:text-base"
                                            style={{
                                                display: "-webkit-box",
                                                WebkitLineClamp: 4,
                                                WebkitBoxOrient: "vertical",
                                            }}
                                        >
                                            {description}
                                        </p>
                                    </div>

                                    {/* Horizontal line */}
                                    <hr className="my-3 border-gray-300" />

                                    {/* Bottom Links */}
                                    <div className="flex justify-between items-center mt-auto">
                                        <motion.a
                                            href={link}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="flex items-center gap-2 font-semibold px-3 py-1 rounded transition-colors duration-300 text-sm sm:text-base"
                                            whileHover={{
                                                backgroundColor: "#E0E7FF",
                                                color: "#1E3A8A",
                                            }}
                                        >
                                            Visit Site <FaExternalLinkAlt />
                                        </motion.a>
                                        <motion.a
                                            href={github}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="p-2 rounded transition-colors duration-300"
                                            whileHover={{
                                                backgroundColor: "#C7D2FE",
                                                color: "#3730A3",
                                            }}
                                        >
                                            <FaGithub />
                                        </motion.a>
                                    </div>
                                </div>
                            </motion.div>
                        )
                    )}
                </div>
            </div>
        </section>
    );
};

export default Projects;
