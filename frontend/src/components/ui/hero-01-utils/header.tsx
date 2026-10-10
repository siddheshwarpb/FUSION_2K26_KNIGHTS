import React from "react"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { Menu, ShieldAlert, Sparkles } from "lucide-react"

export interface NavigationSection {
  title: string
  href: string
  isActive?: boolean
}

interface HeaderProps {
  navigationData: NavigationSection[]
  onScanClick?: () => void
}

export default function Header({ navigationData, onScanClick }: HeaderProps) {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-white/10 bg-black/40 backdrop-blur-md">
      <div className="container mx-auto flex h-16 items-center justify-between px-4 sm:px-8">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600/20 text-blue-400 ring-1 ring-blue-500/30">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <span className="text-base font-bold tracking-tight text-white">PatchOrder</span>
            <span className="ml-2 rounded border border-blue-500/30 bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-400">
              SCA Engine
            </span>
          </div>
        </div>

        {/* Desktop navigation */}
        <nav className="hidden md:flex items-center gap-6">
          {navigationData.map((item) => (
            <a
              key={item.title}
              href={item.href}
              className={`text-sm font-medium transition-colors hover:text-white ${
                item.isActive ? "text-white" : "text-white/60"
              }`}
            >
              {item.title}
            </a>
          ))}
        </nav>

        {/* Desktop CTA */}
        <div className="hidden md:flex items-center gap-3">
          <Button
            size="sm"
            onClick={onScanClick}
            className="bg-blue-600 text-white hover:bg-blue-500 shadow-lg shadow-blue-600/20"
          >
            <Sparkles className="mr-1.5 h-3.5 w-3.5" />
            Upload Manifest
          </Button>
        </div>

        {/* Mobile menu */}
        <div className="md:hidden">
          <Sheet>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon" className="text-white/80">
                <Menu className="h-5 w-5" />
              </Button>
            </SheetTrigger>
            <SheetContent side="right" className="bg-[#161618] border-white/10 text-white">
              <div className="flex flex-col gap-4 mt-8">
                {navigationData.map((item) => (
                  <a
                    key={item.title}
                    href={item.href}
                    className="text-base font-medium text-white/80 hover:text-white"
                  >
                    {item.title}
                  </a>
                ))}
                <Button onClick={onScanClick} className="w-full mt-4 bg-blue-600 text-white">
                  Upload Manifest
                </Button>
              </div>
            </SheetContent>
          </Sheet>
        </div>
      </div>
    </header>
  )
}

