import React from "react";
import { FaTruck, FaLeaf, FaStar, FaHeadset } from "react-icons/fa";

const features = [
    {
        title: "Free Shipping",
        description: "Get your orders delivered to your doorstep without extra cost.",
        icon: FaTruck,
        bgColor: "bg-purple-500",
    },
    {
        title: "Always Fresh",
        description: "Our foods are fresh and carefully selected every day.",
        icon: FaLeaf,
        bgColor: "bg-yellow-500",
    },
    {
        title: "Best Quality",
        description: "We ensure top-quality products for your satisfaction.",
        icon: FaStar,
        bgColor: "bg-blue-500",
    },
    {
        title: "Support",
        description: "Our team is here to help you 24/7 with any query.",
        icon: FaHeadset,
        bgColor: "bg-red-500",
    },
];

const FeaturesSection = () => {
    return (
        <section className="max-w-7xl mx-auto px-4 py-12 sm:py-14 md:py-16">
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-6 sm:gap-8">
                {features.map((feature, idx) => {
                    const Icon = feature.icon;
                    return (
                        <div
                            key={idx}
                            className="group flex flex-col items-center p-4 sm:p-6 rounded-2xl cursor-pointer border-2 border-transparent transition-all duration-300 hover:border-green-500 hover:shadow-lg"
                        >
                            <div
                                className={`w-20 sm:w-24 h-20 sm:h-24 flex items-center justify-center mb-4 rounded-full transition-colors duration-300 ${feature.bgColor} group-hover:bg-white`}
                            >
                                <Icon className="text-white text-5xl sm:text-6xl transition-colors duration-300 group-hover:text-green-500" />
                            </div>
                            <h3 className="text-lg sm:text-xl font-bold mb-2 text-gray-600 group-hover:text-green-500 transition-colors duration-300 text-center">
                                {feature.title}
                            </h3>
                            <p className="text-sm sm:text-base text-gray-500 text-center transition-colors duration-300 group-hover:text-gray-600">
                                {feature.description}
                            </p>
                        </div>
                    );
                })}
            </div>
        </section>
    );
};

export default FeaturesSection;
