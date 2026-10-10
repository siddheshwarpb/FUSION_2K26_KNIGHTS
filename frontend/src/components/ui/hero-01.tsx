import HeroSection from "@/components/ui/hero-01-utils/hero";
import type { NavigationSection } from "@/components/ui/hero-01-utils/header";
import Header from "@/components/ui/hero-01-utils/header";
import BrandSlider, {
  BrandList,
} from "@/components/ui/hero-01-utils/brand-slider";
import type { AvatarList } from "@/components/ui/hero-01-utils/hero";

interface AgencyHeroSectionProps {
  onScanResult?: (data: any) => void
}

export default function AgencyHeroSection({ onScanResult }: AgencyHeroSectionProps) {
  const avatarList: AvatarList[] = [
    {
      image: "https://cdn.21st.dev/assets/localized/59a2b5a0dfc1531e2d1ea42d71ae8615f37582e1f8a17e4a1b1aff9afc7ef878.jpg",
    },
    {
      image: "https://cdn.21st.dev/assets/localized/c7097eeb66ad097b6e5f9dbb95ae857cd6b55c0ad398c1ea84f3ab90a02c631e.jpg",
    },
    {
      image: "https://cdn.21st.dev/assets/localized/c70d48e47d3a2d79ad07d16bff3aa3cff686580be031b6102cad73a15b47d8fd.jpg",
    },
    {
      image: "https://cdn.21st.dev/assets/localized/51c9ed392f6e7fce7fd85a78648e3e06bfdcd91999ab5fa48485888231589abf.jpg",
    },
  ];

  const navigationData: NavigationSection[] = [
    {
      title: "Scanner",
      href: "#scanner",
      isActive: true,
    },
    {
      title: "Propagation Paths",
      href: "#propagation",
    },
    {
      title: "OSV Feeds",
      href: "#osv",
    },
    {
      title: "Architecture",
      href: "#architecture",
    },
  ];

  const brandList: BrandList[] = [
    { name: "npm / JavaScript" },
    { name: "PyPI / Python" },
    { name: "Maven / Java" },
    { name: "OSV.dev Database" },
    { name: "CVE Services" },
    { name: "CISA KEV" },
  ];

  return (
    <div className="relative">
      <Header navigationData={navigationData} />
      <main>
        <HeroSection avatarList={avatarList} onScanResult={onScanResult} />
        <BrandSlider brandList={brandList} />
      </main>
    </div>
  );
}

