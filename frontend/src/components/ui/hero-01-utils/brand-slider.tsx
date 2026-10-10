import React from "react"

export interface BrandList {
  name: string
  image?: string
  lightimg?: string
}

interface BrandSliderProps {
  brandList: BrandList[]
}

export default function BrandSlider({ brandList }: BrandSliderProps) {
  return (
    <section className="py-12 border-t border-white/5 bg-black/20">
      <div className="container mx-auto px-4 text-center">
        <p className="text-xs uppercase tracking-widest text-white/40 mb-6 font-semibold">
          Supported Manifest Ecosystems & Feeds
        </p>
        <div className="flex flex-wrap items-center justify-center gap-8 md:gap-14 opacity-70 grayscale hover:grayscale-0 transition-all duration-300">
          {brandList.map((brand, i) => (
            <div key={i} className="flex items-center gap-2 text-white/80 font-medium text-sm">
              <span className="h-2 w-2 rounded-full bg-blue-500 animate-pulse"></span>
              <span>{brand.name}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

