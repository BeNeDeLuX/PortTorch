export default function Brand() {
  return (
    <span className="brand">
      {/* Both rendered, CSS picks one by data-theme (see .brand-logo-dark/
          .brand-logo-light) - reacts instantly to the theme toggle without
          needing React state here. */}
      <img src="/porttorch-logo-transparent.svg" alt="PortTorch" className="brand-logo brand-logo-dark" />
      <img src="/porttorch-logo-light.svg" alt="PortTorch" className="brand-logo brand-logo-light" />
    </span>
  );
}
