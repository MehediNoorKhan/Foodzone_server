import project1Img from "../../assets/project1.jpg"; // Roommate Finder image
import project2Img from "../../assets/project2.jpeg"; // Food Zone image
import project3Img from "../../assets/project3.png"; // ConvoNest image

export const projects = [
    {
        id: 1,
        title: "Roommate Finder",
        image: project1Img,
        link: "https://assignment-10-faf93.web.app/",
        github: "https://github.com/MehediNoorKhan/Find_Your_Roommate",
        technologies: ["React.js", "Express.js", "Tailwind CSS", "Firebase Auth", "MongoDB"],
        description: "A MERN stack app where users can post roommate listings, show interest in others’ posts, and track their own activities. Connects people looking for compatible roommates in an easy and interactive way.",
    },
    {
        id: 2,
        title: "Food Zone",
        image: project2Img,
        link: "https://assignment11-b015f.web.app/",
        github: "https://github.com/MehediNoorKhan/FoodZone",
        technologies: ["React.js", "Express.js", "MongoDB", "Firebase Auth", "Tailwind CSS", "Framer-Motion", "Stripe"],
        description: "A web app for sharing surplus food with those in need. Users can donate, request, and manage food listings, helping reduce food waste in the community.",
    },
    {
        id: 3,
        title: "ConvoNest",
        image: project3Img,
        link: "https://convonest3.web.app/",
        github: "https://github.com/MehediNoorKhan/Convonest",
        technologies: ["React.js", "Express.js", "MongoDB", "Firebase Auth", "Tailwind CSS", "Stripe"],
        description: "A dynamic discussion platform where users can share posts, engage in conversations, and explore trending topics. Features include user authentication, admin controls, comments, voting, and announcements.",
    },
];
