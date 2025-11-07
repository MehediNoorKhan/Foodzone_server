import { FaQuoteRight, FaStar } from "react-icons/fa";
import { testimonials } from "../data/testimonials";

const Testimonials = () => {
    return (
        <section id="testimonials" className="py-12 bg-white">
            {/* Heading */}
            <div className="text-center mb-12 sm:mb-16 px-4">
                <h2
                    className="text-3xl sm:text-4xl md:text-5xl mb-4 font-bold bg-gradient-to-r from-[#4ade80] via-[#3b82f6] to-[#a78bfa] bg-clip-text text-transparent"
                    style={{ backgroundSize: "20% auto" }}
                >
                    Testimonials
                </h2>
                <p className="text-xl sm:text-2xl text-gray-600 mt-2">What Others Say</p>
                <p className="text-gray-500 mt-1 text-sm sm:text-base">
                    Real feedback from real people who trusted me with their projects.
                </p>
            </div>

            {/* Cards */}
            <div className="max-w-5xl mx-auto grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6 sm:gap-8 px-4 sm:px-6">
                {testimonials.map((t) => (
                    <div
                        key={t.id}
                        className="p-4 sm:p-6 rounded-2xl shadow-md border border-gray-100 bg-gradient-to-b from-white to-gray-50 hover:shadow-lg transition-transform duration-300 hover:-translate-y-1 flex flex-col justify-between h-auto sm:h-[340px]"
                    >
                        <div>
                            {/* Top row: stars & quote */}
                            <div className="flex justify-between items-start">
                                <div className="flex space-x-1">
                                    {[...Array(t.rating)].map((_, i) => (
                                        <FaStar key={i} className="text-yellow-400" />
                                    ))}
                                </div>
                                <div
                                    className="p-2 rounded-md"
                                    style={{ backgroundColor: t.quoteBg }}
                                >
                                    <FaQuoteRight size={18} color={t.quoteColor} />
                                </div>
                            </div>

                            {/* Feedback */}
                            <p
                                className="text-gray-700 mt-4 sm:mt-6 italic leading-relaxed text-ellipsis overflow-hidden text-sm sm:text-base"
                                style={{
                                    display: "-webkit-box",
                                    WebkitLineClamp: 4,
                                    WebkitBoxOrient: "vertical",
                                }}
                            >
                                “{t.feedback}”
                            </p>
                        </div>

                        {/* Bottom section (divider + user info) */}
                        <div className="mt-4 sm:mt-5">
                            <hr className="my-3 sm:my-5 border-gray-200" />
                            <div className="flex items-center">
                                <div
                                    className="w-10 h-10 sm:w-12 sm:h-12 flex items-center justify-center rounded-full font-bold text-base sm:text-lg"
                                    style={{ backgroundColor: t.avatarBg }}
                                >
                                    <span className="text-gray-800">{t.initials}</span>
                                </div>
                                <p className="ml-3 font-semibold text-gray-800 text-sm sm:text-base">
                                    {t.name}
                                </p>
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </section>
    );
};

export default Testimonials;
