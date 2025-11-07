import React, { useEffect, useState } from "react";
import { Link } from "react-router";

const slides = [
    {
        id: 1,
        image:
            "https://images.unsplash.com/photo-1504754524776-8f4f37790ca0?auto=format&fit=crop&w=1600&q=80",
        heading: "Share Food, Spread Love",
        subheading: "Donate your extra food to someone who needs it more.",
        buttonText: "Find Foods",
        buttonLink: "/availablefoods",
    },
    {
        id: 2,
        image:
            "https://images.unsplash.com/photo-1600891964599-f61ba0e24092?auto=format&fit=crop&w=1600&q=80",
        heading: "Be the Reason Someone Eats Today",
        subheading: "Your donation can save someone from hunger.",
        buttonText: "Start Donating",
        buttonLink: "/addfood",
    },
    {
        id: 3,
        image:
            "https://images.unsplash.com/photo-1510626176961-4b57d4fbad03?auto=format&fit=crop&w=1600&q=80",
        heading: "Join the Movement",
        subheading: "Let’s reduce food waste and help each other.",
        buttonText: "How It Works",
        buttonLink: "/about",
    },
];

const Banner = () => {
    const [current, setCurrent] = useState(0);

    useEffect(() => {
        const interval = setInterval(() => {
            setCurrent((prev) => (prev === slides.length - 1 ? 0 : prev + 1));
        }, 5000);
        return () => clearInterval(interval);
    }, []);

    const { image, heading, subheading, buttonText, buttonLink } = slides[current];

    return (
        <div className="relative w-full h-[80vh]">
            <img src={image} alt="Slide" className="w-full h-full object-cover" />

            <div className="absolute inset-0 bg-black/50 flex flex-col items-center justify-center text-center text-white px-4">
                <h1 className="text-5xl sm:text-2xl md:text-5xl font-bold mb-4">{heading}</h1>
                <p className="text-lg md:text-2xl mb-6 max-w-2xl">{subheading}</p>
                <Link
                    to={buttonLink}
                    className="bg-[#22c55e] hover:bg-[#24725e] px-6 py-3 rounded-full text-lg font-semibold shadow-lg transition"
                >
                    {buttonText}
                </Link>
            </div>

            {/* Slider Dots */}
            <div className="absolute bottom-5 left-1/2 -translate-x-1/2 flex space-x-2">
                {slides.map((_, i) => (
                    <button
                        key={i}
                        onClick={() => setCurrent(i)}
                        className={`rounded-full transition-all duration-300 ${i === current
                            ? "w-6 h-3 bg-[#22c55e]" // active: wider and colorful
                            : "w-3 h-3 bg-white/50" // inactive: small and semi-transparent
                            }`}
                    />
                ))}
            </div>
        </div>
    );
};

export default Banner;
