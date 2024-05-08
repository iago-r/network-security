// Define a lista de membros da equipe com suas propriedades
const teamMembers = [
    {
        name: "Francisco",
        role: "Graduando/Desenvolvedor",
        imageSrc: "images/francisco.png",
        socialLinks: {
            github: "https://github.com/Francisco-aragao",
            linkedin: "https://www.linkedin.com/in/francisco-aragão-334b60173/",
        },
    },
    {
        name: "Gabriel",
        role: "Graduando/Desenvolvedor",
        imageSrc: "images/pains.jpg",
        socialLinks: {
            github: "https://github.com/probablygab",
        },
    },
    {
        name: "Lucas",
        role: "Graduando/Desenvolvedor",
        imageSrc: "images/lucas.jpg",
        socialLinks: {
            github: "https://github.com/Sacramento-20",
        },
    },
    {
        name: "Pedro",
        role: "Graduando/Desenvolvedor",
        imageSrc: "images/pedro.jpg",
        socialLinks: {
            github: "https://github.com/Pephma",
        },
    },
    {
        name: "Italo",
        role: "Coordenador",
        imageSrc: "images/italo.jpg",
        socialLinks: {
            github: "https://github.com/cunha",
            linkedin: "https://www.linkedin.com/in/italocunha/",
            user: "http://lattes.cnpq.br/7973706384467274"
        },
    },
];

// Função para criar o elemento do membro da equipe
function createTeamMemberElement(member) {
    const container = document.createElement("div");
    container.className = "col-lg-4 col-sm-6";

    const blogImg = document.createElement("div");
    blogImg.className = "blog_img";
    const img = document.createElement("img");
    img.src = member.imageSrc;
    blogImg.appendChild(img);

    const name = document.createElement("h3");
    name.className = "jonmork_text";
    name.textContent = member.name;

    const role = document.createElement("p");
    role.className = "worker_text";
    role.textContent = member.role;

    const followText = document.createElement("p");
    followText.className = "follow_text";

    const socialIcon = document.createElement("div");
    socialIcon.className = "social_icon";
    const ul = document.createElement("ul");

    // Cria os ícones de redes sociais
    for (const key in member.socialLinks) {
        const li = document.createElement("li");
        const a = document.createElement("a");
        const i = document.createElement("i");

        a.href = member.socialLinks[key];
        i.className = `fa fa-${key}`;
        i.setAttribute("aria-hidden", "true");

        a.appendChild(i);
        li.appendChild(a);
        ul.appendChild(li);
    }

    socialIcon.appendChild(ul);

    container.appendChild(blogImg);
    container.appendChild(name);
    container.appendChild(role);
    container.appendChild(followText);
    container.appendChild(socialIcon);

    return container;
}

// Função para adicionar os membros da equipe ao DOM
function addTeamToPage() {
    const blogSection = document.querySelector(".blog_section_2 .row");

    teamMembers.forEach((member) => {
        const teamElement = createTeamMemberElement(member);
        blogSection.appendChild(teamElement);
    });
}

// Adiciona a equipe ao carregar a página
document.addEventListener("DOMContentLoaded", addTeamToPage);
