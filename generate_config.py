from jinja2 import Environment, FileSystemLoader
from config import configure_topology

def main():

    # Load correct context from topology
    context = configure_topology(senders=3).context

    # Load the template
    file_loader = FileSystemLoader(".")
    env = Environment(
        loader=file_loader,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Render the network templates
    for network_name, network in context["networks"].items():
        template = env.get_template("network_template.xml.j2")
        output = template.render(
            network_name=network_name,
            network=network,
            devices=context["devices"],
        )
        with open(f"{network_name}.xml", "w") as f:
            f.write(output)

    # Render the device templates
    for device_name, device in context["devices"].items():
        template = env.get_template("vm_template.xml.j2")
        output = template.render(device_name=device_name, device=device)
        with open(f"{device_name}.xml", "w") as f:
            f.write(output)

    print("Templates rendered successfully.")


if __name__ == "__main__":
    main()
