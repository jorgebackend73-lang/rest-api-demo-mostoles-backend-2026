package com.example.entities;

import java.io.Serializable;
import java.math.BigDecimal;

import org.springframework.hateoas.RepresentationModel;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity
@Table(name = "products")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
@EqualsAndHashCode(callSuper = false)
@Builder
public class Product implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @NotNull(message = "El producto tiene que tener un nombre")
    @NotEmpty(message = "El nombre del producto no puede estar vacio")
    @Size(min = 4, max = 25, message = "El nombre del producto no puede tener menos de 4 caracteres ni mas de 25")
    private String name;

    @NotNull(message = "La description del producto es requerida")
    @NotBlank(message = "La description del producto no puede tener espacios vacios solamente")
    @Size(max = 45, message = "La description no puede superar los 45 caracteres")
    private String description;

    @Min(value = 0, message = "El stock del producto no puede ser negativo")
    private int stock;

    @Min(value = 0, message = "El precio no puede estar en valores negativos")
    private BigDecimal price;

    @NotNull(message = "La presentación del producto es requerida")
    @ManyToOne(fetch = FetchType.LAZY)
    @JsonIgnoreProperties({ "hibernateLazyInitializer", "handler" })
    private Presentation presentation;

    private String productImage;
}
